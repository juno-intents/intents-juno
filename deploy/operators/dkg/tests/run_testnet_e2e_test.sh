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

  if [[ "$haystack" != *"$first"* ]]; then
    printf 'assert_order failed: %s: first missing=%q\n' "$msg" "$first" >&2
    exit 1
  fi
  if [[ "$haystack" != *"$second"* ]]; then
    printf 'assert_order failed: %s: second missing=%q\n' "$msg" "$second" >&2
    exit 1
  fi

  local after_first
  after_first="${haystack#*"$first"}"
  if [[ "$after_first" != *"$second"* ]]; then
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
  assert_contains "$script_text" '"${scan_url%/}/v1/wallets/${encoded_wallet_id}/notes?limit=2000"' "indexed wallet fallback scans wallet notes for tx visibility"
  assert_contains "$script_text" "reusing indexed witness wallet id for tx visibility" "run-testnet-e2e logs indexed wallet id fallback when generated wallet id has no note visibility"
  assert_contains "$script_text" "switching witness wallet id during extraction" "run-testnet-e2e can switch to an already-indexed wallet id mid-extraction when note visibility stalls"
  assert_contains "$script_text" 'withdraw_coordinator_juno_wallet_id="$generated_wallet_id"' "wallet-id fallback updates withdraw coordinator wallet id for downstream witness extraction"
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
  assert_contains "$script_text" 'witness_scan_backfill_wallet "$witness_scan_url" "$juno_scan_bearer_token" "$generated_wallet_id" "$witness_backfill_from_height"' "run-testnet-e2e proactively backfills each healthy witness scan endpoint before quorum extraction"
  assert_contains "$script_text" "witness backfill best-effort failed for operator=" "run-testnet-e2e keeps extraction resilient when an endpoint backfill fails"
  assert_contains "$script_text" "direct-cli witness backfill best-effort failed" "direct-cli witness extraction path also backfills wallet history before note extraction"
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
  assert_contains "$script_text" "--nonce \"\$run_deposit_nonce\"" "deposit queue payload uses bridge-api nonce from the real deposit memo"
  assert_contains "$script_text" "/v1/status/deposit/" "live bridge flow checks deposit status through bridge-api"
  assert_contains "$script_text" "/v1/status/withdrawal/" "live bridge flow checks withdrawal status through bridge-api"
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

  assert_contains "$script_text" 'set_env_value "$tmp_env" BRIDGE_ADDRESS "$bridge_address"' "checkpoint bridge config updater writes BRIDGE_ADDRESS into operator stack env"
  assert_contains "$script_text" 'set_env_value "$tmp_env" BASE_CHAIN_ID "$base_chain_id"' "checkpoint bridge config updater writes BASE_CHAIN_ID into operator stack env"
  assert_contains "$script_text" 'sudo install -m 0640 -o root -g ubuntu "$tmp_env" "$stack_env_file"' "checkpoint bridge config updater persists mutated operator stack env with expected ownership"
  assert_contains "$script_text" 'checkpoint_signer_script="/usr/local/bin/intents-juno-checkpoint-signer.sh"' "checkpoint bridge config updater targets checkpoint-signer wrapper script"
  assert_contains "$script_text" 'checkpoint_aggregator_script="/usr/local/bin/intents-juno-checkpoint-aggregator.sh"' "checkpoint bridge config updater targets checkpoint-aggregator wrapper script"
  assert_contains "$script_text" 'sudo sed -i "s|^  --base-chain-id .*\\\\$|  --base-chain-id ${base_chain_id} \\\\|g" "$checkpoint_signer_script"' "checkpoint bridge config updater rewrites checkpoint-signer base chain id flag"
  assert_contains "$script_text" 'sudo sed -i "s|^  --bridge-address .*\\\\$|  --bridge-address ${bridge_address} \\\\|g" "$checkpoint_signer_script"' "checkpoint bridge config updater rewrites checkpoint-signer bridge address flag"
  assert_contains "$script_text" 'sudo sed -i "s|^  --base-chain-id .*\\\\$|  --base-chain-id ${base_chain_id} \\\\|g" "$checkpoint_aggregator_script"' "checkpoint bridge config updater rewrites checkpoint-aggregator base chain id flag"
  assert_contains "$script_text" 'sudo sed -i "s|^  --bridge-address .*\\\\$|  --bridge-address ${bridge_address} \\\\|g" "$checkpoint_aggregator_script"' "checkpoint bridge config updater rewrites checkpoint-aggregator bridge address flag"
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

test_shared_ecs_rollout_does_not_shadow_secret_backed_requestor_keys() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_not_contains "$script_text" '{name:"PROOF_REQUESTOR_KEY", value:$requestor_key}' "shared ecs env list does not duplicate secret-backed PROOF_REQUESTOR_KEY"
  assert_not_contains "$script_text" '{name:"PROOF_FUNDER_KEY", value:$funder_key}' "shared ecs env list does not duplicate secret-backed PROOF_FUNDER_KEY"
  assert_contains "$script_text" '{name:"SP1_DEPOSIT_PROGRAM_URL", value:$deposit_program_url}' "shared ecs env list still includes deposit program URL"
  assert_contains "$script_text" '{name:"SP1_WITHDRAW_PROGRAM_URL", value:$withdraw_program_url}' "shared ecs env list still includes withdraw program URL"
}

test_shared_ecs_uses_explicit_sp1_adapter_binary_path() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" '"--sp1-bin" "/usr/local/bin/sp1-prover-adapter"' "shared ecs proof services use explicit sp1 adapter binary path"
  assert_not_contains "$script_text" '"--sp1-bin" "/usr/local/bin/sp1"' "shared ecs proof services no longer rely on /usr/local/bin/sp1 alias"
}

test_shared_ecs_rollout_retries_transient_unstable_services() {
  local script_text
  script_text="$(cat "$TARGET_SCRIPT")"

  assert_contains "$script_text" "wait_for_shared_proof_services_ecs_stable()" "shared ecs rollout defines explicit stability wait helper"
  assert_contains "$script_text" "shared ecs services not stable (attempt" "shared ecs rollout logs each unstable attempt"
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

main() {
  test_base_prefund_budget_preflight_exists_and_runs_before_prefund_loop
  test_base_balance_queries_retry_on_transient_rpc_failures
  test_operator_signer_is_lazy_for_runner_core_flow
  test_witness_pool_uses_per_endpoint_timeout_slices
  test_witness_generation_reuses_distributed_dkg_recipient_identity
  test_witness_metadata_failover_reuses_single_wallet_id
  test_witness_extraction_reuses_existing_indexed_wallet_id
  test_witness_extraction_derives_action_indexes_from_tx_orchard_actions
  test_witness_extraction_backfills_recent_wallet_history_before_quorum_attempts
  test_witness_generation_binds_memos_to_predicted_bridge_domain
  test_live_bridge_flow_uses_bridge_api_and_real_juno_deposit_submission
  test_bridge_address_prediction_parses_cast_labeled_output
  test_direct_cli_user_proof_uses_bridge_specific_witness_generation
  test_direct_cli_user_proof_uses_queue_submission_mode
  test_existing_bridge_summary_reuses_deployed_contracts
  test_checkpoint_bridge_config_updates_stack_env_runtime_keys
  test_direct_cli_witness_extraction_retries_note_visibility
  test_json_array_from_args_separates_jq_options_from_cli_flags
  test_workdir_run_lock_prevents_overlapping_runs
  test_shared_ecs_rollout_does_not_shadow_secret_backed_requestor_keys
  test_shared_ecs_uses_explicit_sp1_adapter_binary_path
  test_shared_ecs_rollout_retries_transient_unstable_services
  test_stop_after_stage_emits_stage_control_and_stops_cleanly
  test_checkpoint_stop_stage_skips_direct_cli_user_proof_scenario
  test_direct_cli_user_proof_is_disabled_by_default_for_runner_orchestration_only
  test_sp1_rpc_defaults_and_validation_target_succinct_network
}

main "$@"
