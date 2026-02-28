#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/../e2e/run-testnet-e2e.sh"

assert_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" != *"$needle"* ]]; then
    printf 'assert_contains failed: %s: missing=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: unexpected=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

assert_order() {
  local haystack="$1"
  local first="$2"
  local second="$3"
  local msg="$4"
  local first_offset second_offset

  first_offset="$(printf '%s' "$haystack" | LC_ALL=C grep -Fbo -m1 -- "$first" | cut -d: -f1 || true)"
  second_offset="$(printf '%s' "$haystack" | LC_ALL=C grep -Fbo -m1 -- "$second" | cut -d: -f1 || true)"

  if [[ -z "$first_offset" ]]; then
    printf 'assert_order failed: %s: first missing=%q\n' "$msg" "$first" >&2
    exit 1
  fi
  if [[ -z "$second_offset" ]]; then
    printf 'assert_order failed: %s: second missing=%q\n' "$msg" "$second" >&2
    exit 1
  fi

  if (( second_offset < first_offset )); then
    printf 'assert_order failed: %s: expected %q before %q\n' "$msg" "$first" "$second" >&2
    exit 1
  fi
}

test_base_prefund_budget_preflight_exists_and_runs_before_prefund_loop() {
  local script_text
  local helper_reference_count
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "assert_prefund_sender_budget()" "prefund budget helper function exists"
  assert_contains "$script_text" "insufficient base funder balance for operator/deployer pre-funding" "prefund insufficiency error message exists"
  helper_reference_count="$(grep -c 'assert_prefund_sender_budget' <<<"$script_text" | tr -d ' ')"
  if (( helper_reference_count < 2 )); then
    printf 'assert_count failed: prefund budget helper must be called (references=%s)\n' "$helper_reference_count" >&2
    exit 1
  fi
  assert_order "$script_text" \
    "assert_prefund_sender_budget" \
    "while IFS= read -r operator; do" \
    "prefund budget check runs before operator prefund loop"
}

test_base_balance_queries_retry_on_transient_rpc_failures() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "read_balance_wei_with_retry()" "cast balance retry helper exists"
  assert_contains "$script_text" "run_with_rpc_retry 6 3 \"cast balance\"" "cast balance reads use rpc retry wrapper"
  assert_contains "$script_text" "failed to read \$label from cast after retries" "recipient balance failure includes explicit retry context"
  assert_contains "$script_text" "base funder balance for pre-fund budget check" "prefund sender balance lookup label is explicit"
  assert_contains "$script_text" "balance=\"\$(read_balance_wei_with_retry \"\$rpc_url\" \"\$recipient\" \"\$label balance\")\"" "recipient prefund loop uses balance retry helper"
  assert_contains "$script_text" "funding_sender_balance_wei=\"\$(read_balance_wei_with_retry \"\$rpc_url\" \"\$funding_sender_address\" \"base funder balance for pre-fund budget check\")\"" "prefund budget check uses balance retry helper"
}

test_bridge_config_contract_reads_retry_on_malformed_rpc_responses() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "is_transient_cast_decode_error() {" "cast decode transient helper exists"
  assert_contains "$script_text" 'if (( call_status == 0 )) && [[ "$raw_response" =~ ^0x[0-9a-fA-F]*$ ]]; then' "contract call helper validates raw cast call hex response before decode"
  assert_contains "$script_text" "cast decode-abi transient error for \$calldata_sig" "contract call helper retries transient decode failures"
  assert_contains "$script_text" "cast call transient/malformed response for \$calldata_sig" "contract call helper retries transient or malformed cast call responses"
  assert_contains "$script_text" 'if (( call_status == 0 )); then' "contract call helper fails explicitly on malformed success-path outputs"
}

test_remote_relayer_service_preserves_quoted_args_over_ssh() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "shell_join() {" "run-testnet-e2e defines shell_join helper used by remote relayer launcher"
  assert_contains "$script_text" "start_remote_relayer_service() {" "run-testnet-e2e defines remote relayer service launcher helper"
  assert_contains "$script_text" 'remote_joined_args="$(shell_join "$@")"' "remote relayer launcher shell-quotes arguments before ssh handoff"
  assert_contains "$script_text" '"bash -lc $(printf '\''%q'\'' "$remote_joined_args")"' "remote relayer launcher executes quoted command via remote bash -lc"
}

test_distributed_relayer_runtime_cleans_stale_processes_before_launch() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "stop_local_relayer_binaries() {" "run-testnet-e2e defines local stale relayer cleanup helper"
  assert_contains "$script_text" '"go run ./cmd/bridge-api"' "local stale cleanup targets prior go-run bridge-api process on runner"
  assert_contains "$script_text" "free_local_tcp_port() {" "run-testnet-e2e defines local tcp listen-port cleanup helper"
  assert_contains "$script_text" 'free_local_tcp_port "$bridge_api_port"' "run-testnet-e2e clears stale bridge-api listen port before restart"
  assert_contains "$script_text" "stopping stale local relayer processes before launch" "run-testnet-e2e logs local stale-process cleanup phase"
  assert_contains "$script_text" "stop_local_relayer_binaries" "run-testnet-e2e invokes local stale-process cleanup helper before relayer startup"
  assert_contains "$script_text" "stop_remote_relayer_binaries_on_host() {" "run-testnet-e2e defines stale remote relayer cleanup helper"
  assert_contains "$script_text" "pkill -f" "stale cleanup uses pkill to stop pre-existing remote relayer binaries"
  assert_contains "$script_text" "/usr/local/bin/[b]ase-relayer" "stale cleanup targets base-relayer binary path with self-match-safe pattern"
  assert_contains "$script_text" "/usr/local/bin/[d]eposit-relayer" "stale cleanup targets deposit-relayer binary path with self-match-safe pattern"
  assert_contains "$script_text" "/usr/local/bin/[w]ithdraw-coordinator" "stale cleanup targets withdraw-coordinator binary path with self-match-safe pattern"
  assert_contains "$script_text" "/usr/local/bin/[w]ithdraw-finalizer" "stale cleanup targets withdraw-finalizer binary path with self-match-safe pattern"
  assert_contains "$script_text" "/usr/local/bin/[b]ridge-api" "stale cleanup targets bridge-api binary path with self-match-safe pattern"
  assert_contains "$script_text" "go run ./cmd/[b]ase-relayer" "remote stale cleanup targets go-run base-relayer process with self-match-safe pattern"
  assert_contains "$script_text" "go run ./cmd/[d]eposit-relayer" "remote stale cleanup targets go-run deposit-relayer process with self-match-safe pattern"
  assert_contains "$script_text" "go run ./cmd/[w]ithdraw-coordinator" "remote stale cleanup targets go-run withdraw-coordinator process with self-match-safe pattern"
  assert_contains "$script_text" "go run ./cmd/[w]ithdraw-finalizer" "remote stale cleanup targets go-run withdraw-finalizer process with self-match-safe pattern"
  assert_contains "$script_text" "go run ./cmd/[b]ridge-api" "remote stale cleanup targets go-run bridge-api process with self-match-safe pattern"
  assert_contains "$script_text" "lsof -t -iTCP" "remote stale cleanup force-frees relayer listen ports"
  assert_contains "$script_text" 'fuser -k \"\${cleanup_port}/tcp\"' "remote stale cleanup uses fuser fallback for occupied ports"
  assert_contains "$script_text" "distributed relayer runtime enabled; stopping stale remote relayer processes before launch" "distributed relayer mode logs stale-process cleanup phase"
  assert_contains "$script_text" 'withdraw_finalizer_host="${relayer_runtime_operator_hosts[0]}"' "distributed relayer mode co-locates withdraw finalizer with base relayer to keep base-relayer sender path local"
  assert_contains "$script_text" 'for relayer_cleanup_host in "${relayer_runtime_operator_hosts[@]}"; do' "distributed relayer mode sweeps full operator host list when cleaning stale relayer services"
  assert_contains "$script_text" "for relayer_cleanup_host in" "distributed relayer mode iterates selected hosts for stale-process cleanup"
  assert_contains "$script_text" "stop_remote_relayer_binaries_on_host \\" "distributed relayer mode invokes stale-process cleanup helper"
  assert_contains "$script_text" 'JUNO_QUEUE_KAFKA_TLS="true"' "distributed relayer runtime forces kafka tls for remote relayer processes"
  assert_contains "$script_text" "failed to stop stale remote relayer processes host=" "stale cleanup failures are logged explicitly"
  assert_contains "$script_text" "marking relayer launch failed" "stale cleanup failures hard-fail relayer startup"
  assert_not_contains "$script_text" "continuing with launch" "stale cleanup failures are no longer treated as best-effort"
}

test_operator_signer_is_lazy_for_runner_core_flow() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "supports_sign_digest_subcommand()" "operator signer capability probe helper exists"
  assert_contains "$script_text" "ensure_bridge_operator_signer_ready()" "operator signer bootstrap is deferred behind an explicit helper"
  assert_contains "$script_text" "ensure_juno_txsign_binary" "operator signer defaults to juno-txsign bootstrap helper"
  assert_contains "$script_text" "bridge_operator_signer_bin=\"juno-txsign\"" "operator signer default prefers juno-txsign command"
  assert_not_contains "$script_text" "write_e2e_operator_digest_signer()" "fallback signer shim writer removed"
  assert_not_contains "$script_text" "does not support sign-digest; using e2e signer shim" "fallback signer shim log removed"
  assert_not_contains "$script_text" "cast wallet sign --no-hash --private-key" "runner-side raw digest signer shim removed"
  assert_contains "$script_text" "go run ./cmd/bridge-e2e --deploy-only \"\${bridge_args[@]}\"" "deploy bootstrap invocation remains present"
  assert_not_contains "$script_text" "env \"\${bridge_operator_signer_env[@]}\" go run ./cmd/bridge-e2e --deploy-only \"\${bridge_args[@]}\"" "deploy bootstrap no longer forces signer env"
  assert_contains "$script_text" "env \"\${bridge_operator_signer_env[@]}\" go run ./cmd/bridge-e2e \"\${direct_cli_bridge_deploy_args[@]}\"" "direct-cli signer path still uses explicit signer env"
  assert_contains "$script_text" "bridge operator signer binary must support sign-digest" "sign-digest capability remains enforced when signer-backed scenarios run"
}

test_withdraw_coordinator_includes_extend_signer_response_limit() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" '--extend-signer-bin "$withdraw_coordinator_extend_signer_bin" \' "withdraw coordinator wires runtime-selected extend signer binary"
  assert_contains "$script_text" "--extend-signer-max-response-bytes \"1048576\" \\" "withdraw coordinator sets explicit extend signer response byte limit"
}

test_withdraw_coordinator_forwards_operator_signer_env() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" $'AWS_DEFAULT_REGION="$distributed_relayer_aws_region" \\\n          "$sp1_witness_juno_rpc_user_env=$withdraw_coordinator_juno_rpc_user_value" \\\n          "$sp1_witness_juno_rpc_pass_env=$withdraw_coordinator_juno_rpc_pass_value" \\\n          "${bridge_operator_signer_env[@]}" \\\n          "$distributed_withdraw_coordinator_bin_path" \\' "distributed withdraw coordinator forwards operator signer env to extend signer binary"
  assert_contains "$script_text" $'BASE_RELAYER_AUTH_TOKEN="$base_relayer_auth_token" \\\n        "${bridge_operator_signer_env[@]}" \\\n        go run ./cmd/withdraw-coordinator \\' "local withdraw coordinator forwards operator signer env to extend signer binary"
}

test_withdraw_coordinator_bootstraps_operator_signer_before_relayer_launch() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "ensuring bridge operator signer for withdraw coordinator relayer flow" "relayer flow logs explicit signer bootstrap gate"
  assert_order "$script_text" \
    "ensuring bridge operator signer for withdraw coordinator relayer flow" \
    '--extend-signer-bin "$withdraw_coordinator_extend_signer_bin" \' \
    "withdraw coordinator signer bootstrap gate runs before coordinator launch arguments"
}

test_distributed_withdraw_coordinator_sets_tss_server_name_override() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'local distributed_withdraw_coordinator_tss_server_name=""' "distributed relayer runtime tracks explicit withdraw coordinator TLS server-name override"
  assert_contains "$script_text" 'distributed_withdraw_coordinator_tss_server_name="$withdraw_coordinator_host"' "distributed relayer runtime binds withdraw coordinator TLS server-name to operator private host"
  assert_contains "$script_text" '--tss-server-name "$distributed_withdraw_coordinator_tss_server_name" \' "withdraw coordinator launch forwards TLS server-name override"
}

test_distributed_relayer_runtime_exports_aws_region_for_s3_artifacts() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'local distributed_relayer_aws_region=""' "distributed relayer runtime tracks resolved aws region for remote relayer env"
  assert_contains "$script_text" 'distributed_relayer_aws_region="$(trim "${AWS_REGION:-${AWS_DEFAULT_REGION:-}}")"' "distributed relayer runtime resolves aws region from live runner environment"
  assert_contains "$script_text" 'AWS_REGION="$distributed_relayer_aws_region"' "distributed relayer runtime forwards aws region to remote relayer processes"
  assert_contains "$script_text" 'AWS_DEFAULT_REGION="$distributed_relayer_aws_region"' "distributed relayer runtime forwards aws default region to remote relayer processes"
}

test_distributed_relayer_runtime_reuses_operator_tls_when_runner_cert_artifacts_missing() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "distributed relayer runtime coordinator client cert/key not present on runner; reusing operator-local TLS material" "distributed relayer runtime logs fallback to operator-local coordinator TLS material in resume mode"
  assert_contains "$script_text" 'distributed_withdraw_coordinator_client_cert_source=""' "distributed relayer runtime can clear runner coordinator cert source when unavailable"
  assert_contains "$script_text" 'distributed_withdraw_coordinator_client_key_source=""' "distributed relayer runtime can clear runner coordinator key source when unavailable"
  assert_not_contains "$script_text" 'die "distributed relayer runtime requires coordinator client cert:' "distributed relayer runtime no longer hard-fails when runner coordinator cert artifact is absent"
  assert_not_contains "$script_text" 'die "distributed relayer runtime requires coordinator client key:' "distributed relayer runtime no longer hard-fails when runner coordinator key artifact is absent"
}

test_distributed_relayer_runtime_stages_coordinator_client_tls_to_operator_host() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'local distributed_withdraw_coordinator_client_cert_file="/tmp/testnet-e2e-coordinator-client.pem"' "distributed relayer runtime defines staged operator-host path for coordinator client cert"
  assert_contains "$script_text" 'local distributed_withdraw_coordinator_client_key_file="/tmp/testnet-e2e-coordinator-client.key"' "distributed relayer runtime defines staged operator-host path for coordinator client key"
  assert_contains "$script_text" '"$distributed_withdraw_coordinator_client_cert_source" \' "distributed relayer runtime stages runner coordinator client cert source"
  assert_contains "$script_text" '"$distributed_withdraw_coordinator_client_cert_file"; then' "distributed relayer runtime copies coordinator client cert to operator-host staging path"
  assert_contains "$script_text" '"$distributed_withdraw_coordinator_client_key_source" \' "distributed relayer runtime stages runner coordinator client key source"
  assert_contains "$script_text" '"$distributed_withdraw_coordinator_client_key_file"; then' "distributed relayer runtime copies coordinator client key to operator-host staging path"
  assert_contains "$script_text" '"$distributed_withdraw_coordinator_client_cert_file" \' "distributed relayer runtime passes staged operator-host cert path into tss-host signer rewiring helper"
  assert_contains "$script_text" '"$distributed_withdraw_coordinator_client_key_file"; then' "distributed relayer runtime passes staged operator-host key path into tss-host signer rewiring helper"
}

test_distributed_relayer_runtime_stages_fresh_binaries_to_operator_hosts() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "stage_remote_runtime_file_atomic() {" "run-testnet-e2e defines helper to stage runtime files via temp-path + atomic move"
  assert_contains "$script_text" 'local remote_temp_path="${remote_path}.tmp.$$"' "atomic staging helper uses per-process temp path to avoid busy-target writes"
  assert_contains "$script_text" "stage_remote_relayer_binaries() {" "run-testnet-e2e defines helper to stage relayer binaries to operator hosts"
  assert_contains "$script_text" "if ! stage_remote_runtime_file_atomic \\" "distributed relayer binary staging hard-fails on per-binary upload/move failure"
  assert_contains "$script_text" "distributed relayer runtime staging freshly built relayer binaries to operator hosts" "distributed relayer runtime logs binary staging phase"
  assert_contains "$script_text" 'local distributed_base_relayer_bin_path="/tmp/testnet-e2e-bin/base-relayer"' "distributed relayer runtime uses staged base-relayer binary path"
  assert_contains "$script_text" 'local distributed_deposit_relayer_bin_path="/tmp/testnet-e2e-bin/deposit-relayer"' "distributed relayer runtime uses staged deposit-relayer binary path"
  assert_contains "$script_text" 'local distributed_withdraw_coordinator_bin_path="/tmp/testnet-e2e-bin/withdraw-coordinator"' "distributed relayer runtime uses staged withdraw-coordinator binary path"
  assert_contains "$script_text" 'local distributed_withdraw_finalizer_bin_path="/tmp/testnet-e2e-bin/withdraw-finalizer"' "distributed relayer runtime uses staged withdraw-finalizer binary path"
  assert_contains "$script_text" 'GO111MODULE=on go build -o "$output_dir/tss-signer" ./cmd/tss-signer' "distributed relayer runtime builds tss-signer for live host patch iteration"
  assert_contains "$script_text" "for bin_name in base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer tss-signer; do" "distributed relayer runtime stages tss-signer alongside relayer binaries"
  assert_contains "$script_text" '"$distributed_base_relayer_bin_path"' "base-relayer launch uses staged binary path"
  assert_contains "$script_text" '"$distributed_deposit_relayer_bin_path"' "deposit-relayer launch uses staged binary path"
  assert_contains "$script_text" '"$distributed_withdraw_coordinator_bin_path"' "withdraw-coordinator launch uses staged binary path"
  assert_contains "$script_text" '"$distributed_withdraw_finalizer_bin_path"' "withdraw-finalizer launch uses staged binary path"
}

test_distributed_relayer_runtime_stages_operator_signer_binary() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'local distributed_bridge_operator_signer_bin=""' "distributed relayer runtime tracks staged operator signer path"
  assert_contains "$script_text" 'distributed_bridge_operator_signer_bin="$distributed_relayer_bin_dir/juno-txsign"' "distributed relayer runtime uses staged juno-txsign path on operator hosts"
  assert_contains "$script_text" 'stage_remote_runtime_file \' "distributed relayer runtime reuses staged file helper for signer binary copy"
  assert_contains "$script_text" '"$runner_bridge_operator_signer_bin_path"' "distributed relayer runtime copies resolved signer binary from runner to operators"
  assert_contains "$script_text" '"$distributed_bridge_operator_signer_bin"' "distributed relayer runtime marks staged signer binary executable on operators"
  assert_contains "$script_text" "configure_remote_tss_host_signer_bin() {" "distributed relayer runtime defines helper to align tss-host signer/tooling runtime paths"
  assert_contains "$script_text" 'remote_signer_wrapper_path="/tmp/testnet-e2e-bin/dkg-admin-spendauth-signer"' "distributed relayer runtime stages a spendauth wrapper with explicit dkg-admin config path"
  assert_contains "$script_text" 'dkg_admin_workdir="/var/lib/intents-juno/operator-runtime/bundle"' "distributed relayer runtime tracks explicit dkg-admin bundle working directory for spendauth signer wrapper"
  assert_contains "$script_text" 'cd "$dkg_admin_workdir"' "distributed relayer runtime spendauth signer wrapper sets dkg-admin working directory before exec"
  assert_contains "$script_text" 'set_env "$tmp_env_file" TSS_SPENDAUTH_SIGNER_BIN "$remote_signer_wrapper_path"' "distributed relayer runtime points tss-host spendauth signer at the staged wrapper"
  assert_contains "$script_text" 'set_env "$tmp_env_file" WITHDRAW_COORDINATOR_EXTEND_SIGNER_BIN "$signer_bin"' "distributed relayer runtime keeps withdraw extension signer aligned with staged juno-txsign binary"
  assert_contains "$script_text" 'sudo ln -sf "$signer_bin" /usr/local/bin/juno-txsign' "distributed relayer runtime ensures tss-signer can find juno-txsign via PATH-stable location"
  assert_contains "$script_text" 'remote_tss_signer_bin="/tmp/testnet-e2e-bin/tss-signer"' "distributed relayer runtime expects staged tss-signer on operator host"
  assert_contains "$script_text" 'sudo ln -sf "$remote_tss_signer_bin" /usr/local/bin/tss-signer' "distributed relayer runtime repoints operator tss-signer to freshly staged binary"
  assert_contains "$script_text" "sudo systemctl restart tss-host.service" "distributed relayer runtime restarts tss-host after signer rewiring"
  assert_contains "$script_text" "if ! configure_remote_tss_host_signer_bin \\" "distributed relayer runtime hard-fails when remote tss-host signer rewiring fails"
  assert_contains "$script_text" '--extend-signer-bin "$withdraw_coordinator_extend_signer_bin" \' "withdraw coordinator launch uses runtime-selected signer binary path"
}

test_distributed_relayer_runtime_persists_base_relayer_auth_token_in_operator_env() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "set_remote_operator_stack_env_value() {" "distributed relayer runtime defines helper to persist operator stack env keys"
  assert_contains "$script_text" 'set_remote_operator_stack_env_value \' "distributed relayer runtime invokes operator stack env persistence helper"
  assert_contains "$script_text" '"BASE_RELAYER_AUTH_TOKEN" \' "distributed relayer runtime forwards base relayer auth token key to operator stack env persistence helper"
  assert_contains "$script_text" '"$base_relayer_auth_token"; then' "distributed relayer runtime forwards per-run auth token value to operator stack env persistence helper"
  assert_contains "$script_text" "distributed relayer runtime failed to persist BASE_RELAYER_AUTH_TOKEN into operator stack env host=" "distributed relayer runtime logs explicit operator stack env persistence failures"
  assert_contains "$script_text" '"WITHDRAW_COORDINATOR_JUNO_WALLET_ID" \' "distributed relayer runtime persists withdraw coordinator wallet id into operator stack env"
  assert_contains "$script_text" '"$withdraw_coordinator_juno_wallet_id"; then' "distributed relayer runtime writes withdraw coordinator wallet id value into operator stack env"
  assert_contains "$script_text" "distributed relayer runtime failed to persist WITHDRAW_COORDINATOR_JUNO_WALLET_ID into operator stack env host=" "distributed relayer runtime logs wallet-id persistence failures"
  assert_contains "$script_text" '"WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS" \' "distributed relayer runtime persists withdraw coordinator change address into operator stack env"
  assert_contains "$script_text" '"$withdraw_coordinator_juno_change_address"; then' "distributed relayer runtime writes withdraw coordinator change address value into operator stack env"
  assert_contains "$script_text" "distributed relayer runtime failed to persist WITHDRAW_COORDINATOR_JUNO_CHANGE_ADDRESS into operator stack env host=" "distributed relayer runtime logs change-address persistence failures"
}

test_withdraw_coordinator_runtime_forwards_juno_scan_inputs() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" $'--juno-wallet-id "$withdraw_coordinator_juno_wallet_id" \\\n          --juno-change-address "$withdraw_coordinator_juno_change_address" \\\n          --juno-fee-add-zat "$withdraw_coordinator_juno_fee_add_zat" \\\n          --juno-scan-url "$distributed_withdraw_coordinator_juno_scan_url" \\\n          --juno-scan-bearer-env "$sp1_witness_juno_scan_bearer_token_env" \\' "distributed withdraw coordinator forwards juno-scan URL and bearer env in its own command path"
  assert_contains "$script_text" $'--juno-wallet-id "$withdraw_coordinator_juno_wallet_id" \\\n          --juno-change-address "$withdraw_coordinator_juno_change_address" \\\n          --juno-fee-add-zat "$withdraw_coordinator_juno_fee_add_zat" \\\n          --juno-scan-url "$sp1_witness_juno_scan_url" \\\n          --juno-scan-bearer-env "$sp1_witness_juno_scan_bearer_token_env" \\' "local withdraw coordinator forwards juno-scan URL and bearer env in its own command path"
}

test_withdraw_coordinator_runtime_sets_explicit_juno_fee_floor() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'local withdraw_coordinator_juno_fee_add_zat="${WITHDRAW_COORDINATOR_JUNO_FEE_ADD_ZAT:-1000000}"' "withdraw coordinator runtime defines explicit juno fee floor override with env escape hatch"
  assert_contains "$script_text" 'local withdraw_coordinator_max_items="${WITHDRAW_COORDINATOR_MAX_ITEMS:-1}"' "withdraw coordinator runtime configures low-latency batch size override for live e2e"
  assert_contains "$script_text" 'local withdraw_coordinator_max_age="${WITHDRAW_COORDINATOR_MAX_AGE:-30s}"' "withdraw coordinator runtime configures low-latency batch age override for live e2e"
  assert_contains "$script_text" '--juno-fee-add-zat "$withdraw_coordinator_juno_fee_add_zat" \' "withdraw coordinator launch passes explicit juno fee floor to txbuild planner"
  assert_contains "$script_text" '--max-items "$withdraw_coordinator_max_items" \' "withdraw coordinator launch passes explicit max-items override"
  assert_contains "$script_text" '--max-age "$withdraw_coordinator_max_age" \' "withdraw coordinator launch passes explicit max-age override"
}

test_withdraw_coordinator_runtime_uses_env_overridable_expiry_windows() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'local withdraw_coordinator_expiry_safety_margin="${WITHDRAW_COORDINATOR_EXPIRY_SAFETY_MARGIN:-4h}"' "withdraw coordinator runtime defaults expiry safety margin to 4h with env override"
  assert_contains "$script_text" 'local withdraw_coordinator_max_expiry_extension="${WITHDRAW_COORDINATOR_MAX_EXPIRY_EXTENSION:-12h}"' "withdraw coordinator runtime defaults max expiry extension to 12h with env override"
  assert_contains "$script_text" '--expiry-safety-margin "$withdraw_coordinator_expiry_safety_margin" \' "withdraw coordinator launch forwards env-overridable expiry safety margin"
  assert_contains "$script_text" '--max-expiry-extension "$withdraw_coordinator_max_expiry_extension" \' "withdraw coordinator launch forwards env-overridable max expiry extension"
}

test_run_restores_bridge_refund_window_baseline_before_live_flow() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'local bridge_min_refund_window_seconds="${BRIDGE_MIN_REFUND_WINDOW_SECONDS:-86400}"' "run-testnet-e2e defines baseline bridge refund window with env override"
  assert_contains "$script_text" 'local bridge_effective_refund_window_floor_seconds="$bridge_min_refund_window_seconds"' "run-testnet-e2e computes effective refund window floor before bridge param restore"
  assert_contains "$script_text" 'if (( bridge_effective_refund_window_floor_seconds > bridge_max_expiry_extension_seconds )); then' "run-testnet-e2e clamps baseline floor to contract max expiry extension when needed"
  assert_contains "$script_text" "bridge effective refund window floor exceeds maxExpiryExtensionSeconds; clamping target" "run-testnet-e2e logs floor clamp when baseline exceeds contract max extension"
  assert_contains "$script_text" 'if (( bridge_refund_window_seconds < bridge_effective_refund_window_floor_seconds )); then' "run-testnet-e2e detects stale low refund window before live relayer flow"
  assert_contains "$script_text" "bridge refundWindowSeconds below baseline; restoring Bridge.setParams(uint96,uint96,uint64,uint64)" "run-testnet-e2e logs baseline bridge param restoration"
  assert_contains "$script_text" "set_bridge_params_with_refund_window_retry \\" "run-testnet-e2e baseline restore uses verified setParams helper with readback retries"
  assert_contains "$script_text" "failed to restore baseline bridge params before relayer launch" "run-testnet-e2e hard-fails when bridge baseline restore transaction fails"
  assert_contains "$script_text" "bridge refundWindowSeconds baseline restore mismatch" "run-testnet-e2e validates baseline refund window after restore"
}

test_live_bridge_flow_treats_equal_withdraw_expiry_as_valid_and_tracks_extension_flag() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'if (( expiry_on_chain < run_withdraw_request_expiry )); then' "run-scoped invariants only fail when on-chain withdraw expiry is below requested expiry"
  assert_not_contains "$script_text" 'if (( expiry_on_chain <= run_withdraw_request_expiry )); then' "run-scoped invariants no longer require expiry growth when request already satisfies coordinator safety margin"
  assert_contains "$script_text" 'if (( expiry_on_chain > run_withdraw_request_expiry )); then' "run-scoped invariants track whether coordinator extended withdrawal expiry beyond requested value"
}

test_operator_down_chaos_prunes_keys_when_endpoint_mode_is_unavailable() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'if [[ "$operator_signer_supports_endpoints" == "true" ]]; then' "operator-down chaos only injects endpoint failure when signer endpoint mode is available"
  assert_contains "$script_text" 'scenario_pid="key-pruned"' "operator-down chaos records synthetic failure id when operating in key-prune mode"
  assert_contains "$script_text" $'if [[ "$operator_signer_supports_endpoints" == "true" ]]; then\n        scenario_pid="$(inject_operator_endpoint_failure "$scenario_endpoint" "$operator_down_ssh_key_path" "$operator_down_ssh_user" || true)"\n        [[ -n "$scenario_pid" ]] || return 1\n      else\n        scenario_pid="key-pruned"\n      fi' "operator-down chaos scopes listener-required checks to endpoint-capable signer mode"
  assert_contains "$script_text" "simulated operator-down by pruning signer key count=" "operator-down chaos logs key-prune simulation path in local-key mode"
}

test_refund_after_expiry_retries_nonce_sensitive_bridge_updates() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "wait_for_bridge_refund_window_seconds() {" "refund window helper waits for on-chain value convergence before failing"
  assert_contains "$script_text" "set_bridge_params_with_refund_window_retry() {" "refund window helper wraps setParams + readback verification"
  assert_contains "$script_text" 'scenario_refund_output="$(' "refund-after-expiry scenario captures verified setParams configure helper output"
  assert_contains "$script_text" 'scenario_restore_output="$(' "refund-after-expiry scenario captures verified setParams restore helper output"
  assert_contains "$script_text" "readback mismatch after setParams attempt=" "refund-after-expiry scenario logs readback mismatch retries before failing"
  assert_contains "$script_text" 'scenario_current_refund_window="$scenario_refund_output"' "refund-after-expiry scenario validates configured refund window from verified helper output"
  assert_contains "$script_text" 'scenario_current_refund_window="$scenario_restore_output"' "refund-after-expiry scenario validates restored refund window from verified helper output"
  assert_contains "$script_text" "refund-after-expiry scenario restore mismatch" "refund-after-expiry scenario validates setParams restore outcome after retries"
  assert_contains "$script_text" "refund-after-expiry scenario retrying withdraw request after nonce race" "refund-after-expiry scenario retries withdraw request when nonce races occur"
}

test_witness_generation_uses_funded_amount_defaults() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" '--deposit-amount-zat "1000000"' "witness metadata generation uses elevated deposit funding default for withdraw payout solvency"
  assert_contains "$script_text" '--withdraw-amount-zat "100000"' "witness metadata generation uses elevated withdraw funding default for withdraw payout solvency"
}

test_witness_pool_uses_per_endpoint_timeout_slices() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "local witness_timeout_slice_seconds" "witness timeout slice variable exists"
  assert_contains "$script_text" "witness_timeout_slice_seconds=\$((sp1_witness_metadata_timeout_seconds / witness_endpoint_healthy_count))" "witness timeout slice divides total timeout by healthy endpoint count"
  assert_contains "$script_text" "(( witness_timeout_slice_seconds >= 300 )) || witness_timeout_slice_seconds=300" "witness timeout slice has a floor for endpoint churn resilience"
  assert_contains "$script_text" "if (( witness_timeout_slice_seconds > sp1_witness_metadata_timeout_seconds )); then" "witness timeout slice is capped by global metadata timeout"
  assert_contains "$script_text" "--timeout-seconds \"\$witness_timeout_slice_seconds\"" "witness metadata generation uses per-endpoint timeout slice"
  assert_contains "$script_text" "witness_extract_deadline_epoch=\$(( \$(date +%s) + witness_timeout_slice_seconds ))" "witness extraction wait loop uses per-endpoint timeout slice"
}

test_witness_metadata_generation_has_hard_process_timeout_guards() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "run_with_optional_timeout() {" "run-testnet-e2e defines helper for hard subprocess timeouts"
  assert_contains "$script_text" 'run_with_optional_timeout "$witness_metadata_attempt_timeout_seconds"' "witness metadata generation is wrapped by hard process timeout guard"
  assert_contains "$script_text" "witness metadata generation timed out for operator=" "witness metadata timeout path is logged with endpoint/operator context"
  assert_contains "$script_text" 'run_with_optional_timeout "$direct_cli_witness_metadata_timeout_seconds"' "direct-cli witness metadata generation is wrapped by hard process timeout guard"
  assert_contains "$script_text" "direct-cli witness metadata generation timed out" "direct-cli witness metadata timeout path is logged"
}

test_witness_pool_retries_endpoint_health_before_quorum_failure() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "local witness_health_retry_timeout_seconds=120" "witness endpoint health retries use an explicit bounded timeout"
  assert_contains "$script_text" "local witness_health_retry_interval_seconds=3" "witness endpoint health retries use a short fixed retry interval"
  assert_contains "$script_text" "witness endpoint quorum not met on first pass; retrying endpoint health checks for up to" "witness endpoint health retry is logged when first-pass quorum is not met"
  assert_contains "$script_text" "witness endpoint became healthy during retry" "witness endpoint health retries log successful recovery transitions"
  assert_contains "$script_text" "after retry window" "witness endpoint quorum failure message includes retry-window context"
}

test_witness_generation_reuses_distributed_dkg_recipient_identity() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "--sp1-witness-recipient-ua" "run-testnet-e2e supports explicit witness recipient UA input"
  assert_contains "$script_text" "--sp1-witness-recipient-ufvk" "run-testnet-e2e supports explicit witness recipient UFVK input"
  assert_contains "$script_text" "--sp1-witness-recipient-ua and --sp1-witness-recipient-ufvk are required for guest witness extraction mode" "guest witness extraction enforces distributed DKG recipient identity inputs"
  assert_contains "$script_text" "--recipient-ua \"\$sp1_witness_recipient_ua\"" "witness metadata generator receives distributed DKG recipient UA"
  assert_contains "$script_text" "--recipient-ufvk \"\$sp1_witness_recipient_ufvk\"" "witness metadata generator receives distributed DKG UFVK"
  assert_contains "$script_text" "generated witness metadata recipient_ua mismatch" "run-testnet-e2e validates generated witness recipient against distributed DKG recipient"
  assert_contains "$script_text" "generated witness metadata ufvk mismatch against distributed DKG value" "run-testnet-e2e validates generated witness UFVK against distributed DKG UFVK"
}

test_witness_metadata_failover_reuses_single_wallet_id() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'witness_wallet_id_attempt="$witness_wallet_id"' "witness metadata failover reuses a single wallet id across endpoint attempts"
  assert_not_contains "$script_text" 'witness_wallet_id_attempt="${witness_wallet_id}-${witness_operator_safe_label}"' "witness metadata failover must not fork wallet ids per endpoint"
}

test_witness_extraction_reuses_existing_indexed_wallet_id() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "witness_scan_find_wallet_for_txid()" "run-testnet-e2e defines helper to locate existing indexed wallet ids by txid"
  assert_contains "$script_text" '"${scan_url%/}/v1/wallets"' "indexed wallet fallback queries scan wallet inventory"
  assert_contains "$script_text" '"${scan_url%/}/v1/wallets/${encoded_wallet_id}/notes?limit=1000"' "indexed wallet fallback scans wallet notes for tx visibility using scanner-supported max page size"
  assert_not_contains "$script_text" '"${scan_url%/}/v1/wallets/${encoded_wallet_id}/notes?limit=2000"' "indexed wallet fallback must not request unsupported scanner page sizes"
  assert_contains "$script_text" "reusing indexed witness wallet id for tx visibility" "run-testnet-e2e logs indexed wallet id fallback when generated wallet id has no note visibility"
  assert_contains "$script_text" "switching witness wallet id during extraction" "run-testnet-e2e can switch to an already-indexed wallet id mid-extraction when note visibility stalls"
  assert_contains "$script_text" 'local witness_extraction_wallet_id=""' "witness extraction tracks a dedicated wallet id independent from withdraw coordinator planner wallet id"
  assert_contains "$script_text" 'witness_extraction_wallet_id="$generated_wallet_id"' "witness extraction initializes dedicated wallet id from generated metadata wallet id"
  assert_not_contains "$script_text" 'withdraw_coordinator_juno_wallet_id="$witness_indexed_wallet_id"' "indexed wallet fallback must not mutate withdraw coordinator planner wallet id"
}

test_witness_extraction_derives_action_indexes_from_tx_orchard_actions() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "witness_rpc_action_index_candidates()" "run-testnet-e2e defines witness action-index candidate derivation helper"
  assert_contains "$script_text" "method:\"getrawtransaction\"" "action-index candidate derivation uses getrawtransaction RPC"
  assert_contains "$script_text" ".result.orchard.actions" "action-index candidate derivation inspects orchard action list"
  assert_contains "$script_text" "--skip-action-index-lookup" "witness metadata generation skips scan action index lookup and delegates action index selection to RPC/quorum extraction"
  assert_contains "$script_text" "for deposit_action_candidate in 0 1 2 3; do" "deposit extraction appends default action-index candidates for scanner/index drift"
  assert_contains "$script_text" "using action-index candidates for deposit extraction" "deposit extraction logs candidate action-index set"
  assert_contains "$script_text" "direct-cli withdraw extraction action-index candidates" "direct-cli withdraw extraction logs candidate action-index set"
  assert_contains "$script_text" 'rm -f "$witness_quorum_dir"/deposit-*.json "$witness_quorum_dir"/deposit-*.witness.bin "$witness_quorum_dir"/deposit-*.extract.err || true' "witness quorum extraction clears stale per-operator artifacts before evaluating quorum"
  assert_contains "$script_text" 'witness_fingerprint="${generated_deposit_txid}|${deposit_witness_hex}|${deposit_final_root}"' "quorum witness fingerprint compares txid+witness+root to reject inconsistent witness content"
  assert_contains "$script_text" "witness_unique_fingerprint_counts" "quorum checker tracks per-fingerprint agreement counts across operators"
  assert_contains "$script_text" "witness_consensus_count" "quorum checker computes strongest fingerprint consensus count"
  assert_contains "$script_text" "witness quorum witness/root divergence detected across operators; selecting consensus fingerprint" "quorum checker tolerates minority anchor drift while enforcing consensus threshold"
  assert_contains "$script_text" "witness quorum anchor divergence detected across operators (using first successful anchor)" "quorum checker reports anchor drift without hard-failing identical witness/root"
}

test_witness_extraction_backfills_recent_wallet_history_before_quorum_attempts() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "witness_rpc_tx_height()" "run-testnet-e2e defines helper to derive tx confirmation height for scan backfill windows"
  assert_contains "$script_text" "witness_scan_backfill_wallet()" "run-testnet-e2e defines helper for scan wallet backfill calls"
  assert_contains "$script_text" "witness backfill tx height unknown; skipping proactive backfill" "run-testnet-e2e logs when tx height is unavailable for proactive scan backfill"
  assert_contains "$script_text" 'witness_scan_backfill_wallet "$witness_scan_url" "$juno_scan_bearer_token" "$witness_extraction_wallet_id" "$witness_backfill_from_height"' "run-testnet-e2e proactively backfills each healthy witness scan endpoint before quorum extraction"
  assert_contains "$script_text" "witness backfill best-effort failed for operator=" "run-testnet-e2e keeps extraction resilient when an endpoint backfill fails"
  assert_contains "$script_text" "direct-cli witness backfill best-effort failed" "direct-cli witness extraction path also backfills wallet history before note extraction"
}

test_relayer_deposit_extraction_backfills_and_reuses_indexed_wallet_id() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "run_deposit_scan_urls=()" "relayer deposit extraction initializes a scan endpoint pool"
  assert_contains "$script_text" "run_deposit_rpc_urls=()" "relayer deposit extraction initializes an rpc endpoint pool"
  assert_contains "$script_text" 'run_deposit_scan_upsert_count="${#run_deposit_scan_urls[@]}"' "relayer deposit extraction computes upsert/backfill fanout from scan pool size"
  assert_contains "$script_text" 'local run_deposit_witness_wallet_id=""' "relayer deposit extraction tracks a dedicated witness wallet id for tx visibility fallback"
  assert_contains "$script_text" 'run_deposit_witness_wallet_id="$withdraw_coordinator_juno_wallet_id"' "relayer deposit extraction initializes dedicated witness wallet id from withdraw coordinator planner wallet id"
  assert_contains "$script_text" 'witness_scan_upsert_wallet "$run_deposit_scan_url" "$juno_scan_bearer_token" "$run_deposit_witness_wallet_id" "$sp1_witness_recipient_ufvk"' "relayer deposit extraction upserts witness wallet across scan endpoints before extraction"
  assert_contains "$script_text" 'witness_scan_backfill_wallet "$run_deposit_scan_url" "$juno_scan_bearer_token" "$run_deposit_witness_wallet_id" "$run_deposit_scan_backfill_from_height"' "relayer deposit extraction proactively backfills witness wallet history from tx-confirmation height"
  assert_contains "$script_text" "run deposit witness backfill tx height unknown; skipping proactive backfill" "relayer deposit extraction logs missing tx-height fallback"
  assert_contains "$script_text" "run deposit witness backfill best-effort failed for scan_url=" "relayer deposit extraction tolerates endpoint-specific backfill failures"
  assert_contains "$script_text" 'witness_scan_find_wallet_for_txid "$run_deposit_scan_url" "$juno_scan_bearer_token" "$run_deposit_juno_tx_hash" "$run_deposit_witness_wallet_id"' "relayer deposit extraction reuses indexed wallet ids when generated wallet id is not visible yet"
  assert_contains "$script_text" "run deposit switching witness wallet id during extraction" "relayer deposit extraction logs indexed-wallet fallback transitions"
  assert_contains "$script_text" "run deposit witness note pending wallet=" "relayer deposit extraction still surfaces note-pending waits with context"
  assert_not_contains "$script_text" 'withdraw_coordinator_juno_wallet_id="$run_deposit_indexed_wallet_id"' "run deposit indexed-wallet fallback must not mutate withdraw coordinator planner wallet id"
  assert_contains "$script_text" "run_deposit_anchor_height" "relayer deposit extraction tracks a checkpoint anchor height for witness extraction"
  assert_contains "$script_text" "run_deposit_anchor_height_latest" "relayer deposit extraction samples latest relayer checkpoint height while waiting for note visibility"
  assert_contains "$script_text" "run deposit witness extraction advanced anchor to relayer checkpoint height=" "relayer deposit extraction refreshes anchor height when relayer checkpoints advance"
  assert_contains "$script_text" 'rm -f "$run_deposit_witness_file" "$run_deposit_extract_json" "$run_deposit_extract_error_file" || true' "relayer deposit extraction clears stale run-deposit witness artifacts before each extraction run"
  assert_contains "$script_text" 'if [[ "$run_deposit_scan_backfill_tx_height" =~ ^[0-9]+$ ]] && (' "relayer deposit extraction ensures anchor selection can compare against run-deposit tx height"
  assert_contains "$script_text" "run deposit witness extraction raised anchor to tx height=" "relayer deposit extraction logs anchor raises when relayer checkpoint lags below tx height"
  assert_contains "$script_text" '--anchor-height "$run_deposit_anchor_height"' "relayer deposit extraction pins juno-witness-extract to the relayer checkpoint anchor height"
  assert_contains "$script_text" "run deposit witness extraction anchored to relayer checkpoint height=" "relayer deposit extraction logs the selected checkpoint anchor height"
}

test_relayer_deposit_extraction_retries_backfill_while_note_pending() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "run_deposit_backfill_retry_interval_seconds=20" "relayer deposit extraction defines periodic backfill retry interval while waiting for note visibility"
  assert_contains "$script_text" "run_deposit_last_backfill_epoch=0" "relayer deposit extraction tracks periodic backfill retry cadence state"
  assert_contains "$script_text" "run deposit witness note pending; retrying scan backfill" "relayer deposit extraction logs periodic backfill retries during note-pending waits"
  assert_contains "$script_text" 'if [[ "$run_deposit_note_pending" == "true" && "$run_deposit_scan_backfill_from_height" =~ ^[0-9]+$ ]]; then' "relayer deposit extraction gates periodic backfill retries on note-pending state and known tx height"
  assert_contains "$script_text" 'if [[ "$run_deposit_note_pending" == "true" && ! "$run_deposit_scan_backfill_tx_height" =~ ^[0-9]+$ ]]; then' "relayer deposit extraction re-queries tx height while note remains pending when initial lookup was unavailable"
  assert_contains "$script_text" "run deposit witness resolved tx height during note-pending retry" "relayer deposit extraction logs delayed tx-height resolution for backfill retries"
  assert_contains "$script_text" "run deposit witness extraction raised anchor to tx height=" "relayer deposit extraction raises anchor floor after delayed tx-height resolution"
}

test_witness_generation_fails_fast_on_funder_insufficient_funds() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'witness_metadata_attempt_err="$workdir/reports/witness/generated-witness-metadata-${witness_operator_safe_label}.err"' "witness metadata generation captures per-endpoint stderr for error classification"
  assert_contains "$script_text" 'if grep -qi "insufficient funds" "$witness_metadata_attempt_err"; then' "witness metadata generation classifies insufficient-funds errors as non-retryable"
  assert_contains "$script_text" 'die "witness metadata generation failed due to insufficient funds for configured JUNO funder source address; top up JUNO_FUNDER_SOURCE_ADDRESS and rerun"' "witness metadata generation fails fast with actionable source-address top-up guidance"
}

test_witness_generation_binds_memos_to_predicted_bridge_domain() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "predicted_witness_bridge_nonce" "run-testnet-e2e computes the deployer nonce for bridge-domain witness planning"
  assert_contains "$script_text" "predicted_witness_bridge_address" "run-testnet-e2e computes the predicted bridge address for witness memo domain separation"
  assert_contains "$script_text" "predicted_witness_withdrawal_id" "run-testnet-e2e computes predicted withdrawal id for witness memo binding"
  assert_contains "$script_text" "predicted_witness_withdraw_batch_id" "run-testnet-e2e computes predicted withdraw batch id for witness memo binding"
  assert_contains "$script_text" '--base-chain-id "$base_chain_id"' "run-testnet-e2e passes base chain id into witness metadata generation"
  assert_contains "$script_text" '--bridge-address "$predicted_witness_bridge_address"' "run-testnet-e2e passes predicted bridge address into witness metadata generation"
  assert_contains "$script_text" '--withdrawal-id-hex "$predicted_witness_withdrawal_id"' "run-testnet-e2e passes predicted withdrawal id into witness metadata generation"
  assert_contains "$script_text" '--withdraw-batch-id-hex "$predicted_witness_withdraw_batch_id"' "run-testnet-e2e passes predicted withdrawal batch id into witness metadata generation"
}

test_live_bridge_flow_uses_bridge_api_and_real_juno_deposit_submission() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "go run ./cmd/bridge-api" "live bridge flow starts bridge-api service"
  assert_contains "$script_text" "/v1/deposit-memo?baseRecipient=" "live bridge flow requests deposit memo from bridge-api"
  assert_contains "$script_text" "z_sendmany" "live bridge flow submits real Juno shielded memo tx"
  assert_contains "$script_text" "z_getoperationstatus" "live bridge flow waits for Juno z_sendmany operation completion"
  assert_contains "$script_text" "juno_wait_tx_confirmed" "live bridge flow waits for mined Juno deposit tx"
  assert_contains "$script_text" "/v1/deposits/submit" "deposit submit is performed through bridge-api write endpoint"
  assert_contains "$script_text" "/v1/withdrawals/request" "withdraw request is performed through bridge-api write endpoint"
  assert_not_contains "$script_text" '"--topic" "$deposit_event_topic"' "runner does not publish deposit events directly; deposit submission stays bridge-api driven"
  assert_not_contains "$script_text" "go run ./cmd/deposit-event" "runner no longer builds deposit queue payload directly"
  assert_contains "$script_text" "/v1/status/deposit/" "live bridge flow checks deposit status through bridge-api"
  assert_contains "$script_text" "/v1/status/withdrawal/" "live bridge flow checks withdrawal status through bridge-api"
}

test_live_bridge_flow_retries_transient_bridge_api_write_failures() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "bridge_api_post_json_with_retry() {" "run-testnet-e2e defines retry helper for bridge-api write endpoints"
  assert_contains "$script_text" "http_status" "bridge-api retry helper captures HTTP status for retry classification"
  assert_contains "$script_text" "bridge-api write retrying" "bridge-api retry helper logs retry context for transient failures"
  assert_contains "$script_text" 'bridge_api_post_json_with_retry "${bridge_api_url}/v1/deposits/submit"' "deposit submit uses bridge-api retry helper"
  assert_contains "$script_text" 'bridge_api_post_json_with_retry "${bridge_api_url}/v1/withdrawals/request"' "withdraw request uses bridge-api retry helper"
}

test_bridge_address_prediction_parses_cast_labeled_output() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "cast compute-address --nonce" "bridge address prediction uses cast compute-address"
  assert_contains "$script_text" "grep -Eo '0x[0-9a-fA-F]{40}'" "bridge address prediction extracts hex address from cast labeled output"
}

test_direct_cli_user_proof_uses_bridge_specific_witness_generation() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "direct-cli-generated-witness-metadata.json" "direct-cli scenario writes dedicated witness metadata"
  assert_contains "$script_text" 'direct_cli_generated_witness_wallet_id="$withdraw_coordinator_juno_wallet_id"' "direct-cli scenario reuses indexed witness wallet id to avoid cold-scan lag"
  assert_contains "$script_text" "direct_cli_generated_deposit_txid" "direct-cli scenario extracts deposit txid from dedicated metadata"
  assert_contains "$script_text" "direct_cli_generated_withdraw_txid" "direct-cli scenario extracts withdraw txid from dedicated metadata"
  assert_contains "$script_text" "direct-cli-deposit.witness.bin" "direct-cli scenario extracts a dedicated deposit witness item"
  assert_contains "$script_text" '--wallet-id "$direct_cli_generated_witness_wallet_id"' "direct-cli withdraw extraction uses dedicated direct-cli witness wallet id"
  assert_contains "$script_text" 'direct_cli_bridge_run_args+=("--sp1-deposit-witness-item-file" "$direct_cli_deposit_witness_file")' "direct-cli bridge run uses dedicated deposit witness"
  assert_contains "$script_text" 'direct_cli_bridge_run_args+=("--sp1-withdraw-witness-item-file" "$direct_cli_withdraw_witness_file")' "direct-cli bridge run uses dedicated withdraw witness"
  assert_contains "$script_text" '"--deposit-final-orchard-root" "$direct_cli_deposit_final_orchard_root"' "direct-cli bridge run overrides deposit orchard root from dedicated witness extraction"
  assert_contains "$script_text" '"--withdraw-final-orchard-root" "$direct_cli_withdraw_final_orchard_root"' "direct-cli bridge run overrides withdraw orchard root from dedicated witness extraction"
}

test_direct_cli_user_proof_uses_queue_submission_mode() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'direct_cli_proof_submission_mode="$sp1_proof_submission_mode"' "direct-cli user proof scenario reuses configured proof submission mode"
  assert_contains "$script_text" '"--sp1-proof-submission-mode" "$direct_cli_proof_submission_mode"' "direct-cli user proof scenario forwards explicit proof submission mode"
  assert_contains "$script_text" '"--sp1-proof-queue-brokers" "$shared_kafka_brokers"' "direct-cli user proof scenario forwards shared proof queue brokers"
  assert_contains "$script_text" '"--sp1-proof-request-topic" "$proof_request_topic"' "direct-cli user proof scenario forwards proof request topic"
  assert_contains "$script_text" '"--sp1-proof-result-topic" "$proof_result_topic"' "direct-cli user proof scenario forwards proof result topic"
  assert_contains "$script_text" '"--sp1-proof-failure-topic" "$proof_failure_topic"' "direct-cli user proof scenario forwards proof failure topic"
  assert_contains "$script_text" '[[ "$direct_cli_user_proof_submission_mode" == "$direct_cli_proof_submission_mode" ]] || return 1' "direct-cli user proof summary validates expected submission mode"
}

test_existing_bridge_summary_reuses_deployed_contracts() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "--existing-bridge-summary-path" "run-testnet-e2e supports existing bridge summary reuse input"
  assert_contains "$script_text" "existing_bridge_summary_path" "run-testnet-e2e tracks existing bridge summary path variable"
  assert_contains "$script_text" 'if [[ -n "$existing_bridge_summary_path" ]]; then' "run-testnet-e2e has conditional branch for existing bridge summary reuse"
  assert_contains "$script_text" 'log "skipping bridge deploy bootstrap; using existing bridge summary path=$bridge_summary"' "run-testnet-e2e logs deploy bootstrap skip when reusing bridge summary"
  assert_contains "$script_text" 'go run ./cmd/bridge-e2e --deploy-only "${bridge_args[@]}"' "run-testnet-e2e retains deploy bootstrap path when no reuse summary is provided"
  assert_order "$script_text" \
    'if [[ -n "$existing_bridge_summary_path" ]]; then' \
    'go run ./cmd/bridge-e2e --deploy-only "${bridge_args[@]}"' \
    "existing bridge summary conditional wraps deploy bootstrap invocation"
}

test_checkpoint_bridge_config_updates_stack_env_runtime_keys() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'mapfile -t checkpoint_operator_ids < <(jq -r '"'"'.operators[].operator_id'"'"' "$dkg_summary")' "checkpoint bridge config updater loads operator addresses from DKG summary"
  assert_contains "$script_text" 'mapfile -t checkpoint_operator_key_files < <(jq -r '"'"'.operators[].operator_key_file // empty'"'"' "$dkg_summary")' "checkpoint bridge config updater loads operator key files from DKG summary"
  assert_contains "$script_text" 'checkpoint_operator_key_hex="$(operator_signer_key_hex_from_file "$checkpoint_operator_key_file" || true)"' "checkpoint bridge config updater derives signer keys from operator key files"
  assert_contains "$script_text" '"$checkpoint_operator_id"' "checkpoint bridge config updater forwards operator address into remote checkpoint config update"
  assert_contains "$script_text" '"$checkpoint_operator_key_hex"' "checkpoint bridge config updater forwards operator signer key into remote checkpoint config update"
  assert_contains "$script_text" '"$shared_postgres_dsn"' "checkpoint bridge config updater forwards shared postgres dsn into remote checkpoint config update"
  assert_contains "$script_text" '"$shared_kafka_brokers"' "checkpoint bridge config updater forwards shared kafka brokers into remote checkpoint config update"
  assert_contains "$script_text" '"$shared_ipfs_api_url"' "checkpoint bridge config updater forwards shared ipfs api url into remote checkpoint config update"
  assert_contains "$script_text" 'set_env_value "$tmp_env" BRIDGE_ADDRESS "$bridge_address"' "checkpoint bridge config updater writes BRIDGE_ADDRESS into operator stack env"
  assert_contains "$script_text" 'set_env_value "$tmp_env" BASE_CHAIN_ID "$base_chain_id"' "checkpoint bridge config updater writes BASE_CHAIN_ID into operator stack env"
  assert_contains "$script_text" 'set_env_value "$tmp_env" AWS_REGION "$aws_region"' "checkpoint bridge config updater writes AWS_REGION into operator stack env"
  assert_contains "$script_text" 'set_env_value "$tmp_env" AWS_DEFAULT_REGION "$aws_region"' "checkpoint bridge config updater writes AWS_DEFAULT_REGION into operator stack env"
  assert_contains "$script_text" 'set_env_value "$tmp_env" CHECKPOINT_POSTGRES_DSN "$shared_postgres_dsn"' "checkpoint bridge config updater writes shared postgres dsn into operator stack env"
  assert_contains "$script_text" 'set_env_value "$tmp_env" CHECKPOINT_KAFKA_BROKERS "$shared_kafka_brokers"' "checkpoint bridge config updater writes shared kafka brokers into operator stack env"
  assert_contains "$script_text" 'set_env_value "$tmp_env" CHECKPOINT_IPFS_API_URL "$shared_ipfs_api_url"' "checkpoint bridge config updater writes shared ipfs api url into operator stack env"
  assert_contains "$script_text" 'set_env_value "$tmp_env" JUNO_QUEUE_KAFKA_TLS "true"' "checkpoint bridge config updater enforces kafka tls in operator stack env"
  assert_contains "$script_text" 'set_env_value "$tmp_env" CHECKPOINT_SIGNER_PRIVATE_KEY "$operator_signer_key_hex"' "checkpoint bridge config updater writes operator DKG signer key into operator stack env"
  assert_contains "$script_text" 'set_env_value "$tmp_env" OPERATOR_ADDRESS "$operator_address"' "checkpoint bridge config updater writes operator DKG address into operator stack env"
  assert_contains "$script_text" 'checkpoint_signer_lease_name="checkpoint-signer-${operator_address#0x}"' "checkpoint bridge config updater derives a per-operator checkpoint signer lease name"
  assert_contains "$script_text" 'set_env_value "$tmp_env" CHECKPOINT_SIGNER_LEASE_NAME "$checkpoint_signer_lease_name"' "checkpoint bridge config updater persists checkpoint signer lease name"
  assert_contains "$script_text" 'sudo install -m 0640 -o root -g ubuntu "$tmp_env" "$stack_env_file"' "checkpoint bridge config updater persists mutated operator stack env with expected ownership"
  assert_contains "$script_text" 'checkpoint_signer_script="/usr/local/bin/intents-juno-checkpoint-signer.sh"' "checkpoint bridge config updater targets checkpoint-signer wrapper script"
  assert_contains "$script_text" 'checkpoint_aggregator_script="/usr/local/bin/intents-juno-checkpoint-aggregator.sh"' "checkpoint bridge config updater targets checkpoint-aggregator wrapper script"
  assert_contains "$script_text" 'sudo sed -i "s|^  --base-chain-id .*\\\\$|  --base-chain-id ${base_chain_id} \\\\|g" "$checkpoint_signer_script"' "checkpoint bridge config updater rewrites checkpoint-signer base chain id flag"
  assert_contains "$script_text" 'sudo sed -i "s|^  --bridge-address .*\\\\$|  --bridge-address ${bridge_address} \\\\|g" "$checkpoint_signer_script"' "checkpoint bridge config updater rewrites checkpoint-signer bridge address flag"
  assert_contains "$script_text" 'if grep -qE '"'"'^[[:space:]]*--lease-name '"'"' "$checkpoint_signer_script"; then' "checkpoint bridge config updater rewrites checkpoint signer lease-name when present"
  assert_contains "$script_text" 'sudo sed -i "s|^[[:space:]]*--lease-name .*|  --lease-name \"${checkpoint_signer_lease_name}\" \\\\|g" "$checkpoint_signer_script"' "checkpoint bridge config updater rewrites existing checkpoint-signer lease-name"
  assert_contains "$script_text" 'awk -v lease="$checkpoint_signer_lease_name"' "checkpoint bridge config updater uses awk insertion to preserve signer command continuation"
  assert_contains "$script_text" 'if (inserted == 0 && $0 ~ /--owner-id /)' "checkpoint bridge config updater prefers inserting lease-name after owner-id"
  assert_contains "$script_text" 'if (inserted == 0 && $0 ~ /--postgres-dsn /)' "checkpoint bridge config updater falls back to inserting lease-name before postgres-dsn when owner-id shape is unexpected"
  assert_contains "$script_text" 'printf "  --lease-name \"%s\" %c\n", lease, 92' "checkpoint bridge config updater writes lease-name with exactly one trailing command-continuation backslash"
  assert_contains "$script_text" 'if (inserted == 0) {' "checkpoint bridge config updater includes a last-resort lease-name insertion guard"
  assert_contains "$script_text" 'sudo install -m 0755 "$lease_tmp" "$checkpoint_signer_script"' "checkpoint bridge config updater atomically writes checkpoint-signer wrapper after lease insertion"
  assert_contains "$script_text" 'sudo sed -i "s|^  --base-chain-id .*\\\\$|  --base-chain-id ${base_chain_id} \\\\|g" "$checkpoint_aggregator_script"' "checkpoint bridge config updater rewrites checkpoint-aggregator base chain id flag"
  assert_contains "$script_text" 'sudo sed -i "s|^  --bridge-address .*\\\\$|  --bridge-address ${bridge_address} \\\\|g" "$checkpoint_aggregator_script"' "checkpoint bridge config updater rewrites checkpoint-aggregator bridge address flag"
  assert_contains "$script_text" 'local aws_region="$8"' "checkpoint bridge config updater accepts aws region as explicit input"
  assert_contains "$script_text" 'local shared_postgres_dsn="$9"' "checkpoint bridge config updater accepts shared postgres dsn as explicit input"
  assert_contains "$script_text" 'local shared_kafka_brokers="${10}"' "checkpoint bridge config updater accepts shared kafka brokers as explicit input"
  assert_contains "$script_text" 'local shared_ipfs_api_url="${11}"' "checkpoint bridge config updater accepts shared ipfs api url as explicit input"
  assert_contains "$script_text" 'resolve_aws_region "$aws_region"' "checkpoint bridge config updater resolves aws region via explicit/env/imds fallback"
  assert_contains "$script_text" 'die "checkpoint bridge config update requires resolvable aws region for host=$host"' "checkpoint bridge config updater fails fast when aws region cannot be resolved"
  assert_contains "$script_text" 'die "checkpoint bridge config update requires shared postgres dsn for host=$host"' "checkpoint bridge config updater fails fast when shared postgres dsn is missing"
  assert_contains "$script_text" 'die "checkpoint bridge config update requires shared kafka brokers for host=$host"' "checkpoint bridge config updater fails fast when shared kafka brokers are missing"
  assert_contains "$script_text" 'die "checkpoint bridge config update requires shared ipfs api url for host=$host"' "checkpoint bridge config updater fails fast when shared ipfs api url is missing"
  assert_contains "$script_text" '.CHECKPOINT_POSTGRES_DSN = $shared_postgres_dsn' "checkpoint bridge config updater rewrites checkpoint postgres dsn in operator stack config json"
  assert_contains "$script_text" '.CHECKPOINT_KAFKA_BROKERS = $shared_kafka_brokers' "checkpoint bridge config updater rewrites checkpoint kafka brokers in operator stack config json"
  assert_contains "$script_text" '.CHECKPOINT_IPFS_API_URL = $shared_ipfs_api_url' "checkpoint bridge config updater rewrites checkpoint ipfs api url in operator stack config json"
}

test_shared_checkpoint_validation_retries_with_relaxed_min_persisted_at_window() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "shared_validation_no_fresh_package_pattern='no operator checkpoint package with IPFS CID found in checkpoint_packages persisted_at >='" "shared checkpoint validation detects no-fresh-package failure signature"
  assert_contains "$script_text" "run_shared_infra_validation_attempt() {" "shared checkpoint validation wraps shared-infra invocation in reusable helper"
  assert_contains "$script_text" 'run_shared_infra_validation_attempt "$checkpoint_started_at" 2>&1 | tee "$shared_validation_log"' "shared checkpoint validation first checks for fresh packages since checkpoint start"
  assert_contains "$script_text" 'checkpoint_relaxed_min_persisted_at="$(date -u -d "$checkpoint_started_at - 30 minutes" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || true)"' "shared checkpoint validation derives a relaxed fallback persisted-at window"
  assert_contains "$script_text" "shared infra validation found no fresh checkpoint package after checkpoint_started_at=" "shared checkpoint validation logs relaxed-window retry context"
  assert_contains "$script_text" 'run_shared_infra_validation_attempt "$checkpoint_relaxed_min_persisted_at" 2>&1 | tee -a "$shared_validation_log"' "shared checkpoint validation retries once with relaxed persisted-at window"
  assert_contains "$script_text" '[[ "$stop_after_stage" == "checkpoint_validated" ]]' "checkpoint validation applies canary-only fallback guard on stop-after-stage"
  assert_contains "$script_text" '[[ -n "$existing_bridge_summary_path" ]]' "checkpoint validation applies canary-only fallback guard on existing bridge summary reuse"
  assert_contains "$script_text" 'checkpoint_canary_min_persisted_at="$(date -u -d "$checkpoint_started_at - 6 hours" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || true)"' "shared checkpoint validation derives extended fallback persisted-at window for resume canary runs"
  assert_contains "$script_text" 'run_shared_infra_validation_attempt "$checkpoint_canary_min_persisted_at" 2>&1 | tee -a "$shared_validation_log"' "shared checkpoint validation retries with extended window for checkpoint-stage resume canaries"
}

test_relayer_runtime_seeds_checkpoint_after_startup() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'run_shared_infra_validation_attempt "$relayer_checkpoint_seed_started_at" "$relayer_checkpoint_seed_summary"' "relayer runtime seeds a fresh checkpoint package after relayers start"
  assert_contains "$script_text" 'relayer runtime checkpoint seed found no fresh checkpoint package after relayer startup; retrying with relaxed checkpoint-min-persisted-at=' "relayer runtime checkpoint seed logs relaxed persisted-at retry context"
  assert_contains "$script_text" 'run_shared_infra_validation_attempt "$relayer_checkpoint_seed_relaxed_min_persisted_at" "$relayer_checkpoint_seed_summary" 2>&1 | tee -a "$relayer_checkpoint_seed_log"' "relayer runtime checkpoint seed retries with relaxed persisted-at window when no fresh package exists"
  assert_contains "$script_text" 'run_shared_infra_validation_attempt "$relayer_checkpoint_seed_resume_min_persisted_at" "$relayer_checkpoint_seed_summary" 2>&1 | tee -a "$relayer_checkpoint_seed_log"' "relayer runtime checkpoint seed retries with extended persisted-at window during resume runs"
  assert_contains "$script_text" "replaying latest checkpoint package onto relayer checkpoint topic after startup" "relayer runtime logs checkpoint replay step after relayer startup"
  assert_contains "$script_text" "SELECT convert_from(package_json, 'UTF8')" "relayer runtime reloads latest persisted checkpoint package payload from postgres"
  assert_contains "$script_text" 'go run ./cmd/queue-publish \' "relayer runtime replays checkpoint payload through queue-publish"
  assert_contains "$script_text" '"--topic" "$checkpoint_package_topic"' "relayer runtime publishes replayed checkpoint payload onto active checkpoint package topic"
  assert_contains "$script_text" '"--payload-file" "$relayer_checkpoint_replay_payload_file"' "relayer runtime publishes checkpoint replay payload via temp file"
  assert_contains "$script_text" 'wait_for_log_pattern "$deposit_relayer_log" "updated checkpoint" 180' "relayer runtime waits for deposit-relayer checkpoint ingestion before deposit submission"
  assert_contains "$script_text" 'wait_for_log_pattern "$withdraw_finalizer_log" "updated checkpoint" 180' "relayer runtime waits for withdraw-finalizer checkpoint ingestion before withdrawal flow"
}

test_direct_cli_witness_extraction_retries_note_visibility() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "direct_cli_deposit_extract_deadline_epoch" "direct-cli deposit extraction has a retry deadline"
  assert_contains "$script_text" "direct-cli waiting for deposit note visibility" "direct-cli deposit extraction logs note-visibility wait state"
  assert_contains "$script_text" "direct_cli_deposit_extract_error_file" "direct-cli deposit extraction captures extraction errors for retry classification"
  assert_contains "$script_text" "direct_cli_withdraw_extract_deadline_epoch" "direct-cli withdraw extraction has a retry deadline"
  assert_contains "$script_text" "direct-cli waiting for withdraw note visibility" "direct-cli withdraw extraction logs note-visibility wait state"
  assert_contains "$script_text" "direct_cli_withdraw_extract_error_file" "direct-cli withdraw extraction captures extraction errors for retry classification"
  assert_contains "$script_text" "for direct_cli_action_candidate in 0 1 2 3; do" "direct-cli extraction appends default action-index candidates for resilience"
}

test_json_array_from_args_separates_jq_options_from_cli_flags() {
  local function_body output
  function_body="$(
    awk '
      /^json_array_from_args\(\)/ { in_fn = 1 }
      in_fn { print }
      in_fn && /^}/ { exit }
    ' "$TARGET_SCRIPT"
  )"
  [[ -n "$function_body" ]] || {
    printf 'failed to extract json_array_from_args from %s\n' "$TARGET_SCRIPT" >&2
    exit 1
  }

  output="$(
    (
      eval "$function_body"
      json_array_from_args "/usr/local/bin/proof-requestor" "--postgres-dsn" "postgres://example"
    )
  )"
  assert_contains "$output" '"/usr/local/bin/proof-requestor"' "json array includes absolute binary path as positional value"
  assert_contains "$output" '"--postgres-dsn"' "json array preserves cli flag arguments"
  assert_contains "$output" '"postgres://example"' "json array preserves cli flag values"
}

test_workdir_run_lock_prevents_overlapping_runs() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "acquire_workdir_run_lock()" "run-testnet-e2e defines a workdir run lock helper"
  assert_contains "$script_text" 'local lock_dir="$workdir/.run.lock"' "workdir lock uses a deterministic per-workdir lock path"
  assert_contains "$script_text" 'die "another run-testnet-e2e.sh process is already active for workdir=$workdir pid=$lock_owner_pid"' "active workdir lock holder causes hard failure"
  assert_contains "$script_text" "trap release_workdir_run_lock EXIT" "workdir lock registers cleanup trap"
  assert_contains "$script_text" 'acquire_workdir_run_lock "$workdir"' "command_run acquires lock before executing live flow"
}

test_wait_for_condition_preserves_check_fn_side_effects() {
  local function_body
  function_body="$(
    awk '
      /^wait_for_condition\(\) {/ { in_fn=1 }
      in_fn { print }
      in_fn && /^}/ { exit }
    ' "$TARGET_SCRIPT"
  )"
  [[ -n "$function_body" ]] || {
    printf 'failed to extract wait_for_condition from %s\n' "$TARGET_SCRIPT" >&2
    exit 1
  }

  assert_contains "$function_body" 'wait_output_file="$(mktemp "${TMPDIR:-/tmp}/wait-for-condition.XXXXXX")"' "wait_for_condition allocates a dedicated output temp file"
  assert_contains "$function_body" '"$@" >"$wait_output_file" 2>&1' "wait_for_condition executes check callback directly (no command substitution subshell)"
  assert_not_contains "$function_body" 'output="$("$@" 2>&1)"' "wait_for_condition no longer uses command substitution that drops callback side effects"
}

test_shared_ecs_rollout_does_not_shadow_secret_backed_requestor_keys() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_not_contains "$script_text" '{name:"PROOF_REQUESTOR_KEY", value:$requestor_key}' "shared ecs env list does not duplicate secret-backed PROOF_REQUESTOR_KEY"
  assert_not_contains "$script_text" '{name:"PROOF_FUNDER_KEY", value:$funder_key}' "shared ecs env list does not duplicate secret-backed PROOF_FUNDER_KEY"
  assert_not_contains "$script_text" '{name:"SP1_MAX_GAS_LIMIT", value:$sp1_global_max_gas_limit}' "shared ecs env list does not force a global SP1 gas cap"
  assert_not_contains "$script_text" '{name:"SP1_DEPOSIT_MAX_GAS_LIMIT", value:$sp1_deposit_max_gas_limit}' "shared ecs env list does not force a deposit SP1 gas cap"
  assert_not_contains "$script_text" '{name:"SP1_WITHDRAW_MAX_GAS_LIMIT", value:$sp1_withdraw_max_gas_limit}' "shared ecs env list does not force a withdraw SP1 gas cap"
  assert_contains "$script_text" '{name:"SP1_DEPOSIT_PROGRAM_URL", value:$deposit_program_url}' "shared ecs env list still includes deposit program URL"
  assert_contains "$script_text" '{name:"SP1_WITHDRAW_PROGRAM_URL", value:$withdraw_program_url}' "shared ecs env list still includes withdraw program URL"
}

test_shared_ecs_uses_explicit_sp1_adapter_binary_path() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" '"--sp1-bin" "/usr/local/bin/sp1-prover-adapter"' "shared ecs proof services use explicit sp1 adapter binary path"
  assert_not_contains "$script_text" '"--sp1-bin" "/usr/local/bin/sp1"' "shared ecs proof services no longer rely on /usr/local/bin/sp1 alias"
}

test_shared_ecs_env_enforces_kafka_tls_for_proof_services() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" '{name:"JUNO_QUEUE_KAFKA_TLS", value:"true"}' "shared ecs proof service env forces kafka tls for msk transport"
}

test_shared_ecs_rollout_retries_transient_unstable_services() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "shared_ecs_services_stability_reason()" "shared ecs rollout defines explicit bounded stability reason probe"
  assert_contains "$script_text" "wait_for_shared_proof_services_ecs_stable()" "shared ecs rollout defines explicit stability wait helper"
  assert_not_contains "$script_text" "aws ecs wait services-stable" "shared ecs rollout no longer blocks on AWS waiter defaults"
  assert_contains "$script_text" "shared ecs services not stable (attempt" "shared ecs rollout logs each unstable attempt"
  assert_contains "$script_text" 'reason=$stability_reason' "shared ecs rollout logs machine-readable stability reason on unstable attempts"
  assert_contains "$script_text" "ecs_events_indicate_transient_bootstrap_failure()" "shared ecs rollout classifies transient bootstrap failures"
  assert_contains "$script_text" "ResourceInitializationError" "shared ecs rollout recognizes ecs resource initialization startup failures"
  assert_contains "$script_text" "rolling out shared proof services retry deployment after transient startup failure" "shared ecs rollout retries deployment when startup failures are transient"
  assert_contains "$script_text" "shared ecs services failed to stabilize after retries" "shared ecs rollout fails with explicit stabilization error after retries"
}

test_stop_after_stage_emits_stage_control_and_stops_cleanly() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "write_stage_checkpoint_summary()" "run-testnet-e2e defines stage checkpoint summary helper"
  assert_contains "$script_text" "maybe_stop_after_stage()" "run-testnet-e2e defines stop-after-stage coordinator helper"
  assert_contains "$script_text" "stop_centralized_proof_services()" "run-testnet-e2e defines reusable proof service shutdown helper"
  assert_contains "$script_text" 'maybe_stop_after_stage "witness_ready"' "run-testnet-e2e evaluates witness_ready stage checkpoint"
  assert_contains "$script_text" 'maybe_stop_after_stage "shared_services_ready"' "run-testnet-e2e evaluates shared_services_ready stage checkpoint"
  assert_contains "$script_text" 'maybe_stop_after_stage "checkpoint_validated"' "run-testnet-e2e evaluates checkpoint_validated stage checkpoint"
  assert_contains "$script_text" "stage checkpoint reached; stopping run at stage=" "run-testnet-e2e logs stage checkpoint early-stop decisions"
  assert_contains "$script_text" "stage_control: {" "run-testnet-e2e summary includes machine-readable stage control block"
  assert_contains "$script_text" 'requested_stop_after_stage: $stop_after_stage' "stage control captures requested stop stage"
  assert_contains "$script_text" "completed_stage: \"full\"" "full summary marks completed stage as full"
  assert_contains "$script_text" "bridge_config_updates_target" "stage control reports checkpoint bridge config update target count"
  assert_contains "$script_text" "bridge_config_updates_succeeded" "stage control reports checkpoint bridge config update success count"
  assert_contains "$script_text" "shared_validation_passed" "stage control reports shared checkpoint validation status"
}

test_checkpoint_stop_stage_skips_direct_cli_user_proof_scenario() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'if [[ "$stop_after_stage" == "checkpoint_validated" ]]; then' "checkpoint stop-stage branch is explicitly handled before direct-cli proof scenario"
  assert_contains "$script_text" 'direct_cli_user_proof_status="skipped-stop-after-stage-checkpoint_validated"' "checkpoint stop-stage records direct-cli proof scenario as skipped"
  assert_contains "$script_text" "skipping direct-cli user proof scenario for stop-after-stage=checkpoint_validated" "checkpoint stop-stage logs direct-cli proof skip reason"
}

test_checkpoint_stop_stage_with_existing_summary_does_not_require_bridge_proof_inputs() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'local require_bridge_proof_inputs="true"' "bridge proof/deploy input validation tracks stage-aware requirement gate"
  assert_contains "$script_text" 'if [[ -n "$existing_bridge_summary_path" && "$stop_after_stage" != "full" ]]; then' "bridge proof/deploy input validation gate drops hard requirements for pre-full stop stages when reusing existing summary"
  assert_contains "$script_text" 'require_bridge_proof_inputs="false"' "bridge proof/deploy input validation gate can be disabled for checkpoint canary runs"
  assert_contains "$script_text" "skipping bridge proof/deploy input validation for stop-after-stage=" "checkpoint canary logs when bridge proof/deploy input validation is intentionally skipped"
  assert_contains "$script_text" 'if [[ "$require_bridge_proof_inputs" == "true" ]]; then' "bridge proof/deploy input requirements remain enforced for full runs"
}

test_direct_cli_user_proof_is_disabled_by_default_for_runner_orchestration_only() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'if [[ "${JUNO_E2E_ENABLE_DIRECT_CLI_USER_PROOF:-0}" != "1" ]]; then' "direct-cli user proof scenario is opt-in"
  assert_contains "$script_text" 'direct_cli_user_proof_status="skipped-runner-orchestration-only"' "direct-cli user proof records orchestration-only default skip status"
  assert_contains "$script_text" "skipping direct-cli user proof scenario; runner SP1 proof submission is disabled" "direct-cli user proof skip reason documents shared-service SP1 ownership"
}

test_sp1_rpc_defaults_and_validation_target_succinct_network() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'local sp1_rpc_url="https://rpc.mainnet.succinct.xyz"' "run-testnet-e2e defaults sp1 rpc to succinct network rpc"
  assert_not_contains "$script_text" 'local sp1_rpc_url="https://mainnet.base.org"' "run-testnet-e2e no longer defaults sp1 rpc to base chain rpc"
  assert_contains "$script_text" "must be a Succinct prover network RPC" "run-testnet-e2e validates sp1 rpc endpoint class"
  assert_contains "$script_text" 'local sp1_verifier_router_address="0x397A5f7f3dBd538f23DE225B51f532c34448dA9B"' "run-testnet-e2e defaults sp1 verifier router to canonical base verifier"
  assert_contains "$script_text" 'local sp1_set_verifier_address="0x397A5f7f3dBd538f23DE225B51f532c34448dA9B"' "run-testnet-e2e defaults sp1 set-verifier to canonical base verifier"
}

test_shared_infra_validation_precreates_bridge_and_proof_topics() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" '--required-kafka-topics "${checkpoint_signature_topic},${checkpoint_package_topic},${proof_request_topic},${proof_result_topic},${proof_failure_topic},${deposit_event_topic},${withdraw_request_topic}"' "shared infra validation pre-creates proof/deposit/withdraw topics before bridge-api and relayer traffic"
}

test_shared_proof_services_restart_after_topic_ensure() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "restarting shared ECS proof-requestor/proof-funder services after shared Kafka topic ensure to refresh consumer assignments" "shared proof services are force-restarted after topic ensure"
  assert_contains "$script_text" 'die "shared ecs services failed to stabilize after post-topic-ensure restart"' "shared proof service post-topic restart has explicit hard-fail message"
  assert_order "$script_text" \
    'run_shared_infra_validation_attempt "$checkpoint_started_at"' \
    "restarting shared ECS proof-requestor/proof-funder services after shared Kafka topic ensure to refresh consumer assignments" \
    "shared proof services restart runs after shared kafka topic ensure/validation"
  assert_order "$script_text" \
    "restarting shared ECS proof-requestor/proof-funder services after shared Kafka topic ensure to refresh consumer assignments" \
    'maybe_stop_after_stage "checkpoint_validated"' \
    "checkpoint canary stage gate runs after post-topic shared service restart"
}

test_relayer_runtime_clears_stale_bridge_rows_before_launch() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "clear_live_bridge_runtime_state() {" "run-testnet-e2e defines helper to clear stale bridge runtime rows"
  assert_contains "$script_text" "DELETE FROM proof_events;" "stale bridge cleanup clears proof event rows"
  assert_contains "$script_text" "DELETE FROM proof_jobs;" "stale bridge cleanup clears proof job rows"
  assert_contains "$script_text" "DELETE FROM proof_request_ids;" "stale bridge cleanup resets deterministic proof request id rows"
  assert_contains "$script_text" "DELETE FROM withdrawal_batch_items;" "stale bridge cleanup clears withdrawal batch item rows"
  assert_contains "$script_text" "DELETE FROM withdrawal_batches;" "stale bridge cleanup clears withdrawal batch rows"
  assert_contains "$script_text" "DELETE FROM withdrawal_requests;" "stale bridge cleanup clears withdrawal request rows"
  assert_contains "$script_text" "DELETE FROM deposit_jobs WHERE state <> 6;" "stale bridge cleanup removes non-finalized deposit rows that can poison new checkpoint batches"
  assert_contains "$script_text" "clearing stale bridge runtime rows from shared postgres before relayer launch" "run-testnet-e2e logs explicit stale bridge cleanup phase before relayer launch"
  assert_order "$script_text" \
    "clearing stale bridge runtime rows from shared postgres before relayer launch" \
    "log \"stopping stale local relayer processes before launch\"" \
    "stale bridge runtime cleanup runs before relayer launch and process bootstrapping"
  assert_contains "$script_text" "failed to clear stale bridge runtime rows from shared postgres" "stale bridge cleanup has explicit hard-fail path"
}

test_live_bridge_flow_self_heals_stalled_proof_requestor_before_failing_deposit_status_wait() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "proof_jobs_count() {" "run-testnet-e2e defines helper to read proof_jobs count from shared postgres"
  assert_contains "$script_text" "restart_shared_proof_services_with_wait() {" "run-testnet-e2e defines helper to restart shared proof services with stability wait"
  assert_contains "$script_text" "proof_requestor_progress_guard_interval_seconds" "run-testnet-e2e defines explicit proof-requestor progress guard interval"
  assert_contains "$script_text" 'local proof_requestor_progress_guard_interval_seconds="$((10#${sp1_auction_timeout%s}))"' "proof-requestor progress guard interval is derived from SP1 auction timeout"
  assert_contains "$script_text" '(( proof_requestor_progress_guard_interval_seconds >= 300 )) || proof_requestor_progress_guard_interval_seconds=300' "proof-requestor progress guard interval enforces minimum stabilization cooldown before restart"
  assert_contains "$script_text" "proof_requestor_progress_guard_max_restarts" "run-testnet-e2e bounds self-heal restarts for stalled proof-requestor progress"
  assert_not_contains "$script_text" "proof_requestor_progress_observed=\"false\"" "run-testnet-e2e no longer permanently disables guard checks after first proof_jobs growth event"
  assert_contains "$script_text" "proof_jobs_count_before_run_deposit" "run-testnet-e2e snapshots proof_jobs count before run deposit submission"
  assert_contains "$script_text" "proof_jobs_latest_updated_epoch() {" "run-testnet-e2e defines helper to read latest proof_jobs updated_at epoch from shared postgres"
  assert_contains "$script_text" "proof_jobs_last_update_epoch_before_run_deposit" "run-testnet-e2e snapshots proof_jobs latest updated_at epoch before run deposit submission"
  assert_contains "$script_text" 'proof_jobs_count_before_run_deposit="$proof_jobs_count_current"' "run-testnet-e2e advances proof_jobs baseline after each observed growth event"
  assert_contains "$script_text" 'proof_jobs_last_update_epoch_before_run_deposit="$proof_jobs_last_update_epoch_current"' "run-testnet-e2e advances proof_jobs updated_at baseline when in-flight proof rows progress"
  assert_contains "$script_text" 'proof_requestor_progress_guard_last_probe_epoch="$now_epoch"' "run-testnet-e2e resets stall probe timer when proof_jobs growth is observed"
  assert_contains "$script_text" "sp1_progress_guard_bump_max_price_per_pgu" "run-testnet-e2e defines a bounded SP1 guardrail bump target for stalled proof submissions"
  assert_contains "$script_text" "proof_jobs_count_current" "run-testnet-e2e reads current proof_jobs count during deposit-status wait"
  assert_contains "$script_text" "proof_jobs_last_update_epoch_current" "run-testnet-e2e reads current proof_jobs updated_at epoch during deposit-status wait"
  assert_contains "$script_text" 'if [[ "$state" == "pending" || "$state" == "confirmed" ]]' "proof-requestor progress guard applies while deposit status is non-finalized confirmed/pending"
  assert_contains "$script_text" "proof-requestor progress observed via proof_jobs updated_at advancement while deposit status is pending" "run-testnet-e2e treats in-place proof job progress as guard activity"
  assert_contains "$script_text" "proof-requestor progress guard: no proof_jobs growth observed while deposit status is non-finalized state=" "run-testnet-e2e logs explicit self-heal reason with current non-finalized deposit state"
  assert_contains "$script_text" "proof-requestor progress guard bumped SP1 max price per PGU" "run-testnet-e2e escalates SP1 max price when pending proof jobs stall"
  assert_contains "$script_text" 'proof_requestor_ecs_environment_json="$(build_proof_requestor_ecs_environment_json)"' "run-testnet-e2e rebuilds shared proof-requestor ecs env after SP1 max-price escalation"
  assert_contains "$script_text" 'proof_requestor_progress_restart_attempts=$((proof_requestor_progress_restart_attempts + 1))' "run-testnet-e2e increments bounded proof-requestor restart attempts"
  assert_contains "$script_text" "proof-requestor progress guard exhausted restarts without proof_jobs growth while deposit status is non-finalized state=" "run-testnet-e2e fails explicitly when bounded self-heal attempts are exhausted"
  assert_contains "$script_text" 'local bridge_api_deposit_wait_timeout_seconds="$((sp1_request_timeout_seconds + 600))"' "deposit status wait timeout is derived from sp1 request timeout plus buffer"
  assert_contains "$script_text" 'wait_for_condition "$bridge_api_deposit_wait_timeout_seconds" 5 "bridge-api deposit status" wait_bridge_api_deposit_finalized' "deposit status wait uses derived timeout window"
  assert_contains "$script_text" 'log "bridge-api deposit did not finalize state=$bridge_api_deposit_state"' "deposit status wait fails fast when terminal non-final state is observed"
  assert_contains "$script_text" 'echo "state=$state"' "deposit status wait surfaces current bridge-api state to pending logs"
  assert_order "$script_text" \
    "proof_jobs_count_before_run_deposit" \
    "bridge_api_post_json_with_retry \"\${bridge_api_url}/v1/deposits/submit\"" \
    "proof-requestor progress baseline is captured before bridge-api deposit submission"
  assert_order "$script_text" \
    "proof_jobs_count_before_run_deposit" \
    "wait_for_condition \"\$bridge_api_deposit_wait_timeout_seconds\" 5 \"bridge-api deposit status\" wait_bridge_api_deposit_finalized" \
    "proof-requestor progress baseline is captured before bridge-api deposit status wait begins"
}

test_relayer_submit_timeout_is_aligned_with_sp1_request_timeout() {
  local script_text
  local submit_timeout_reference_count
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" 'local sp1_request_timeout_seconds="$((10#${sp1_request_timeout%s}))"' "run-testnet-e2e parses sp1 request timeout seconds for relayer timeout alignment"
  assert_contains "$script_text" 'local relayer_submit_timeout_seconds="$((sp1_request_timeout_seconds + 300))"' "run-testnet-e2e derives relayer submit timeout from sp1 request timeout plus safety buffer"
  assert_contains "$script_text" '(( relayer_submit_timeout_seconds >= 1800 )) || relayer_submit_timeout_seconds=1800' "run-testnet-e2e enforces a floor submit-timeout for long-running live proofs"
  assert_contains "$script_text" 'local relayer_submit_timeout="${relayer_submit_timeout_seconds}s"' "run-testnet-e2e formats relayer submit timeout as duration string"
  assert_contains "$script_text" '--submit-timeout "$relayer_submit_timeout" \' "relayer launch paths pass explicit submit-timeout override"
  submit_timeout_reference_count="$(grep -c -- '--submit-timeout "\$relayer_submit_timeout"' <<<"$script_text" | tr -d ' ')"
  if (( submit_timeout_reference_count < 4 )); then
    printf 'assert_count failed: expected submit-timeout override in all relayer launch paths (count=%s)\n' "$submit_timeout_reference_count" >&2
    exit 1
  fi
}

test_shared_ecs_rollout_accepts_explicit_proof_services_image_override() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "--shared-proof-services-image <image>" "run-testnet-e2e usage documents shared proof services image override"
  assert_contains "$script_text" 'local shared_proof_services_image=""' "run-testnet-e2e tracks shared proof services image override option"
  assert_contains "$script_text" "--shared-proof-services-image)" "run-testnet-e2e parses shared proof services image override argument"
  assert_contains "$script_text" 'local container_image="${7:-}"' "ecs task definition helper accepts optional container image override"
  assert_contains "$script_text" '| .image = (if ($container_image | length) > 0 then $container_image else .image end)' "ecs task definition helper overwrites container image when override is set"
  assert_contains "$script_text" 'local shared_proof_services_image="${9:-}"' "shared ecs rollout helper accepts proof services image override"
  assert_contains "$script_text" '"$shared_proof_services_image"' "shared ecs rollout forwards image override through task definition registration"
  assert_contains "$script_text" "overriding shared ECS proof services image image=" "run-testnet-e2e logs explicit shared proof services image override usage"
}

test_run_deposit_submission_waits_for_relayer_checkpoint_catchup() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "latest_checkpoint_height_from_log() {" "run-testnet-e2e defines helper to parse latest relayer checkpoint height from logs"
  assert_contains "$script_text" "wait_for_relayer_checkpoint_height_at_least() {" "run-testnet-e2e defines helper to gate on relayer checkpoint catch-up"
  assert_contains "$script_text" "run deposit waiting for relayer checkpoint catch-up" "run-testnet-e2e logs explicit relayer checkpoint wait before submitting deposit"
  assert_contains "$script_text" "run_deposit_submit_min_checkpoint_height" "run-testnet-e2e computes the deposit tx checkpoint floor before submit"
  assert_contains "$script_text" 'wait_for_relayer_checkpoint_height_at_least "$deposit_relayer_log" "$run_deposit_submit_min_checkpoint_height" 300' "run-testnet-e2e enforces relayer checkpoint >= deposit tx height before bridge-api submit"
  assert_order "$script_text" \
    "run_deposit_submit_min_checkpoint_height" \
    'bridge_api_post_json_with_retry "${bridge_api_url}/v1/deposits/submit"' \
    "run-testnet-e2e computes checkpoint floor before bridge-api deposit submission"
}

main() {
  test_base_prefund_budget_preflight_exists_and_runs_before_prefund_loop
  test_base_balance_queries_retry_on_transient_rpc_failures
  test_bridge_config_contract_reads_retry_on_malformed_rpc_responses
  test_remote_relayer_service_preserves_quoted_args_over_ssh
  test_distributed_relayer_runtime_cleans_stale_processes_before_launch
  test_operator_signer_is_lazy_for_runner_core_flow
  test_withdraw_coordinator_includes_extend_signer_response_limit
  test_withdraw_coordinator_forwards_operator_signer_env
  test_withdraw_coordinator_bootstraps_operator_signer_before_relayer_launch
  test_distributed_withdraw_coordinator_sets_tss_server_name_override
  test_distributed_relayer_runtime_exports_aws_region_for_s3_artifacts
  test_distributed_relayer_runtime_reuses_operator_tls_when_runner_cert_artifacts_missing
  test_distributed_relayer_runtime_stages_coordinator_client_tls_to_operator_host
  test_distributed_relayer_runtime_stages_fresh_binaries_to_operator_hosts
  test_distributed_relayer_runtime_stages_operator_signer_binary
  test_distributed_relayer_runtime_persists_base_relayer_auth_token_in_operator_env
  test_withdraw_coordinator_runtime_forwards_juno_scan_inputs
test_withdraw_coordinator_runtime_sets_explicit_juno_fee_floor
  test_withdraw_coordinator_runtime_uses_env_overridable_expiry_windows
  test_run_restores_bridge_refund_window_baseline_before_live_flow
  test_live_bridge_flow_treats_equal_withdraw_expiry_as_valid_and_tracks_extension_flag
  test_operator_down_chaos_prunes_keys_when_endpoint_mode_is_unavailable
  test_refund_after_expiry_retries_nonce_sensitive_bridge_updates
test_witness_generation_uses_funded_amount_defaults
test_witness_pool_uses_per_endpoint_timeout_slices
  test_witness_metadata_generation_has_hard_process_timeout_guards
  test_witness_pool_retries_endpoint_health_before_quorum_failure
  test_witness_generation_reuses_distributed_dkg_recipient_identity
  test_witness_metadata_failover_reuses_single_wallet_id
  test_witness_extraction_reuses_existing_indexed_wallet_id
  test_witness_extraction_derives_action_indexes_from_tx_orchard_actions
  test_witness_extraction_backfills_recent_wallet_history_before_quorum_attempts
  test_relayer_deposit_extraction_backfills_and_reuses_indexed_wallet_id
  test_relayer_deposit_extraction_retries_backfill_while_note_pending
  test_witness_generation_fails_fast_on_funder_insufficient_funds
  test_witness_generation_binds_memos_to_predicted_bridge_domain
  test_live_bridge_flow_uses_bridge_api_and_real_juno_deposit_submission
  test_live_bridge_flow_retries_transient_bridge_api_write_failures
  test_bridge_address_prediction_parses_cast_labeled_output
  test_direct_cli_user_proof_uses_bridge_specific_witness_generation
  test_direct_cli_user_proof_uses_queue_submission_mode
  test_existing_bridge_summary_reuses_deployed_contracts
  test_checkpoint_bridge_config_updates_stack_env_runtime_keys
  test_shared_checkpoint_validation_retries_with_relaxed_min_persisted_at_window
  test_relayer_runtime_seeds_checkpoint_after_startup
  test_direct_cli_witness_extraction_retries_note_visibility
  test_json_array_from_args_separates_jq_options_from_cli_flags
  test_workdir_run_lock_prevents_overlapping_runs
  test_wait_for_condition_preserves_check_fn_side_effects
  test_shared_ecs_rollout_does_not_shadow_secret_backed_requestor_keys
  test_shared_ecs_uses_explicit_sp1_adapter_binary_path
  test_shared_ecs_env_enforces_kafka_tls_for_proof_services
  test_shared_ecs_rollout_retries_transient_unstable_services
  test_stop_after_stage_emits_stage_control_and_stops_cleanly
  test_checkpoint_stop_stage_skips_direct_cli_user_proof_scenario
  test_checkpoint_stop_stage_with_existing_summary_does_not_require_bridge_proof_inputs
  test_direct_cli_user_proof_is_disabled_by_default_for_runner_orchestration_only
  test_sp1_rpc_defaults_and_validation_target_succinct_network
  test_shared_infra_validation_precreates_bridge_and_proof_topics
  test_shared_proof_services_restart_after_topic_ensure
  test_relayer_runtime_clears_stale_bridge_rows_before_launch
  test_live_bridge_flow_self_heals_stalled_proof_requestor_before_failing_deposit_status_wait
  test_relayer_submit_timeout_is_aligned_with_sp1_request_timeout
  test_shared_ecs_rollout_accepts_explicit_proof_services_image_override
  test_run_deposit_submission_waits_for_relayer_checkpoint_catchup
}

main "$@"
