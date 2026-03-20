#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

usage() {
  cat <<'EOF'
Usage:
  rehearse-rollout.sh [options]

Options:
  --inventory PATH               Deployment inventory JSON (required for new runs)
  --dkg-summary PATH             DKG summary JSON (required for new runs)
  --bridge-deploy-binary PATH    Bridge deploy binary (required unless reusing bridge summary)
  --deployer-key-file PATH       Deployer key file (required when deploying bridge)
  --funder-key-file PATH         Funder key file for bridge-deploy ephemeral mode
  --ephemeral-funding-amount-wei AMOUNT
                                 Wei amount to fund a generated ephemeral deployer
  --sweep-recipient ADDRESS      Optional sweep recipient for the ephemeral deployer
  --existing-bridge-summary PATH Reuse an existing bridge summary instead of deploying
  --terraform-output-json PATH   Use a precomputed terraform output -json file
  --skip-terraform-apply         Do not run terraform init/apply during coordinator generation
  --output-root DIR              Rehearsal root (default: ./tmp/production-rehearsal)
  --run-id ID                    Optional run directory label (default: run-<timestamp>)
  --resume-run-dir DIR           Resume an existing rehearsal run directory instead of generating a new one
  --pause-after-operator-count N Stop after N successful operator rollouts to prove resume behavior
  --dry-run                      Forward dry-run mode to deploy/canary commands

Environment overrides:
  PRODUCTION_DEPLOY_COORDINATOR_BIN
  PRODUCTION_DEPLOY_OPERATOR_BIN
  PRODUCTION_CANARY_SHARED_BIN
  PRODUCTION_CANARY_OPERATOR_BIN
EOF
}

inventory=""
dkg_summary=""
bridge_deploy_binary=""
deployer_key_file=""
funder_key_file=""
ephemeral_funding_amount_wei=""
sweep_recipient=""
existing_bridge_summary=""
terraform_output_json=""
skip_terraform_apply="false"
output_root="$REPO_ROOT/tmp/production-rehearsal"
run_id=""
resume_run_dir=""
pause_after_operator_count=""
dry_run="false"

deploy_coordinator_bin="${PRODUCTION_DEPLOY_COORDINATOR_BIN:-$SCRIPT_DIR/deploy-coordinator.sh}"
deploy_operator_bin="${PRODUCTION_DEPLOY_OPERATOR_BIN:-$SCRIPT_DIR/deploy-operator.sh}"
canary_shared_bin="${PRODUCTION_CANARY_SHARED_BIN:-$SCRIPT_DIR/canary-shared-services.sh}"
canary_operator_bin="${PRODUCTION_CANARY_OPERATOR_BIN:-$SCRIPT_DIR/canary-operator-boot.sh}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory) inventory="$2"; shift 2 ;;
    --dkg-summary) dkg_summary="$2"; shift 2 ;;
    --bridge-deploy-binary) bridge_deploy_binary="$2"; shift 2 ;;
    --deployer-key-file) deployer_key_file="$2"; shift 2 ;;
    --funder-key-file) funder_key_file="$2"; shift 2 ;;
    --ephemeral-funding-amount-wei) ephemeral_funding_amount_wei="$2"; shift 2 ;;
    --sweep-recipient) sweep_recipient="$2"; shift 2 ;;
    --existing-bridge-summary) existing_bridge_summary="$2"; shift 2 ;;
    --terraform-output-json) terraform_output_json="$2"; shift 2 ;;
    --skip-terraform-apply) skip_terraform_apply="true"; shift ;;
    --output-root) output_root="$2"; shift 2 ;;
    --run-id) run_id="$2"; shift 2 ;;
    --resume-run-dir) resume_run_dir="$2"; shift 2 ;;
    --pause-after-operator-count) pause_after_operator_count="$2"; shift 2 ;;
    --dry-run) dry_run="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

for cmd in jq "$deploy_coordinator_bin" "$deploy_operator_bin" "$canary_shared_bin" "$canary_operator_bin"; do
  have_cmd "$cmd" || [[ -x "$cmd" ]] || die "required command not found: $cmd"
done

run_dir=""
run_env=""
copied_inventory_path=""
generated_at="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
paused_rehearsal="false"

summary_operator_lines() {
  local state_file="$1"
  local canary_dir="$2"
  jq -r '
    .operators[]
    | [.operator_id, .status, (.note // "")] | @tsv
  ' "$state_file" | while IFS=$'\t' read -r operator_id status note; do
    local safe_id canary_path canary_status
    safe_id="$(production_safe_slug "$operator_id")"
    canary_path="$canary_dir/${safe_id}.json"
    canary_status="not-run"
    if [[ -f "$canary_path" ]]; then
      canary_status="$(jq -r '.ready_for_deploy' "$canary_path" 2>/dev/null || echo "unknown")"
    fi
    printf '| `%s` | `%s` | `%s` | %s |\n' "$operator_id" "$status" "$canary_status" "$note"
  done
}

write_summary() {
  local run_dir="$1"
  local env_slug="$2"
  local summary_path="$run_dir/summary.md"
  local state_file="$run_dir/rollout-state.json"
  local shared_canary="$run_dir/canaries/shared-services.json"
  local shared_status

  shared_status="not-run"
  if [[ -f "$shared_canary" ]]; then
    shared_status="$(jq -r '.ready_for_deploy' "$shared_canary" 2>/dev/null || echo "unknown")"
  fi

  {
    printf '# Production Rehearsal Summary\n\n'
    printf -- '- Generated at: `%s`\n' "$generated_at"
    printf -- '- Environment: `%s`\n' "$env_slug"
    printf -- '- Run dir: `%s`\n' "$run_dir"
    printf -- '- Deployment inventory snapshot: `%s`\n' "$copied_inventory_path"
    printf -- '- Shared canary ready: `%s`\n' "$shared_status"
    printf '\n## Artifacts\n\n'
    printf -- '- [deployment-inventory.json](%s)\n' "$run_dir/deployment-inventory.json"
    printf -- '- [bridge-summary.json](%s)\n' "$run_dir/bridge-summary.json"
    printf -- '- [shared-manifest.json](%s)\n' "$run_dir/shared-manifest.json"
    if [[ -f "$run_dir/shared-terraform-output.json" ]]; then
      printf -- '- [shared-terraform-output.json](%s)\n' "$run_dir/shared-terraform-output.json"
    fi
    if [[ -f "$run_dir/app-terraform-output.json" ]]; then
      printf -- '- [app-terraform-output.json](%s)\n' "$run_dir/app-terraform-output.json"
    fi
    if [[ -f "$run_dir/terraform-output.json" ]]; then
      printf -- '- [terraform-output.json](%s)\n' "$run_dir/terraform-output.json"
    fi
    printf -- '- [rollout-state.json](%s)\n' "$state_file"
    printf -- '- [canaries](%s)\n' "$run_dir/canaries"
    printf '\n## Operator Status\n\n'
    printf '| Operator | Rollout | Canary Ready | Note |\n'
    printf '| --- | --- | --- | --- |\n'
    summary_operator_lines "$state_file" "$run_dir/canaries"
  } >"$summary_path"
}

copy_run_inputs() {
  local src_inventory="$1"
  local src_dkg_summary="$2"
  local src_existing_bridge_summary="$3"

  copied_inventory_path="$run_dir/deployment-inventory.json"
  cp "$src_inventory" "$copied_inventory_path"
  cp "$src_dkg_summary" "$run_dir/dkg-summary.json"
  if [[ -n "$src_existing_bridge_summary" ]]; then
    cp "$src_existing_bridge_summary" "$run_dir/original-bridge-summary.json"
  fi
}

run_shared_canary() {
  local shared_manifest="$1"
  local output_json="$run_dir/canaries/shared-services.json"
  local -a args=("$canary_shared_bin" --shared-manifest "$shared_manifest")
  if [[ "$dry_run" == "true" ]]; then
    args+=(--dry-run)
  fi
  "${args[@]}" >"$output_json"
  [[ "$(jq -r '.ready_for_deploy' "$output_json")" == "true" ]] || die "shared services canary failed: $output_json"
}

run_operator_canary() {
  local manifest="$1"
  local operator_id output_json
  operator_id="$(jq -r '.operator_id' "$manifest")"
  output_json="$run_dir/canaries/$(production_safe_slug "$operator_id").json"
  local -a args=("$canary_operator_bin" --operator-deploy "$manifest")
  if [[ "$dry_run" == "true" ]]; then
    args+=(--dry-run)
  fi
  "${args[@]}" >"$output_json"
  [[ "$(jq -r '.ready_for_deploy' "$output_json")" == "true" ]] || die "operator canary failed for $operator_id: $output_json"
}

operator_manifest_paths() {
  local run_dir="$1"
  jq -r '.operators[].operator_id' "$run_dir/rollout-state.json" | while IFS= read -r operator_id; do
    printf '%s/operator-deploy.json\n' "$(production_operator_dir "$run_dir" "$operator_id")"
  done
}

completed_operator_count() {
  local state_file="$1"
  jq '[.operators[] | select(.status == "done")] | length' "$state_file"
}

deploy_next_operators() {
  local state_file="$run_dir/rollout-state.json"
  local deployed_this_invocation
  deployed_this_invocation=0

  while IFS= read -r manifest; do
    [[ -f "$manifest" ]] || die "operator manifest not found: $manifest"
    local operator_id status
    operator_id="$(jq -r '.operator_id' "$manifest")"
    status="$(jq -r --arg operator_id "$operator_id" '.operators[] | select(.operator_id == $operator_id) | .status' "$state_file")"
    case "$status" in
      done)
        continue
        ;;
      pending|failed|in_progress)
        ;;
      *)
        die "unsupported rollout state for $operator_id: $status"
        ;;
    esac

    local -a deploy_args=("$deploy_operator_bin" --operator-deploy "$manifest")
    if [[ "$dry_run" == "true" ]]; then
      deploy_args+=(--dry-run)
    fi
    "${deploy_args[@]}"
    run_operator_canary "$manifest"
    deployed_this_invocation=$((deployed_this_invocation + 1))
    write_summary "$run_dir" "$run_env"

    if [[ -n "$pause_after_operator_count" ]]; then
      local total_done
      total_done="$(completed_operator_count "$state_file")"
      if (( total_done >= pause_after_operator_count )); then
        log "pausing rehearsal after $total_done operators to allow explicit resume"
        paused_rehearsal="true"
        return 0
      fi
    fi
  done < <(operator_manifest_paths "$run_dir")
}

if [[ -n "$resume_run_dir" ]]; then
  [[ -z "$inventory" && -z "$dkg_summary" ]] || die "--resume-run-dir cannot be combined with --inventory or --dkg-summary"
  run_dir="$(production_abs_path "$PWD" "$resume_run_dir")"
  [[ -d "$run_dir" ]] || die "resume run dir not found: $run_dir"
  [[ -f "$run_dir/shared-manifest.json" ]] || die "shared manifest missing from resume run dir: $run_dir"
  [[ -f "$run_dir/rollout-state.json" ]] || die "rollout state missing from resume run dir: $run_dir"
  [[ -f "$run_dir/deployment-inventory.json" ]] || die "deployment inventory snapshot missing from resume run dir: $run_dir"
  copied_inventory_path="$run_dir/deployment-inventory.json"
  run_env="$(jq -r '.environment' "$run_dir/shared-manifest.json")"
else
  [[ -n "$inventory" ]] || die "--inventory is required for a new rehearsal run"
  [[ -f "$inventory" ]] || die "inventory not found: $inventory"
  [[ -n "$dkg_summary" ]] || die "--dkg-summary is required for a new rehearsal run"
  [[ -f "$dkg_summary" ]] || die "dkg summary not found: $dkg_summary"

  run_env="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
  if [[ -z "$run_id" ]]; then
    run_id="run-$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  run_dir="$(production_abs_path "$PWD" "$output_root")/$run_env/$(production_safe_slug "$run_id")"
  mkdir -p "$run_dir/canaries"

  copy_run_inputs "$inventory" "$dkg_summary" "$existing_bridge_summary"

  coordinator_args=(
    "$deploy_coordinator_bin"
    --inventory "$inventory"
    --dkg-summary "$dkg_summary"
    --output-dir "$(production_abs_path "$PWD" "$output_root")"
    --run-label "$run_id"
  )
  if [[ -n "$existing_bridge_summary" ]]; then
    coordinator_args+=(--existing-bridge-summary "$existing_bridge_summary")
  else
    [[ -n "$bridge_deploy_binary" ]] || die "--bridge-deploy-binary is required when bridge summary is not reused"
    if [[ -n "$deployer_key_file" ]]; then
      coordinator_args+=(--bridge-deploy-binary "$bridge_deploy_binary" --deployer-key-file "$deployer_key_file")
    else
      coordinator_args+=(--bridge-deploy-binary "$bridge_deploy_binary")
    fi
    if [[ -n "$funder_key_file" ]]; then
      coordinator_args+=(--funder-key-file "$funder_key_file")
    fi
    if [[ -n "$ephemeral_funding_amount_wei" ]]; then
      coordinator_args+=(--ephemeral-funding-amount-wei "$ephemeral_funding_amount_wei")
    fi
    if [[ -n "$sweep_recipient" ]]; then
      coordinator_args+=(--sweep-recipient "$sweep_recipient")
    fi
  fi
  if [[ -n "$terraform_output_json" ]]; then
    coordinator_args+=(--terraform-output-json "$terraform_output_json")
  fi
  if [[ "$skip_terraform_apply" == "true" ]]; then
    coordinator_args+=(--skip-terraform-apply)
  fi
  if [[ "$dry_run" == "true" ]]; then
    coordinator_args+=(--dry-run)
  fi

  "${coordinator_args[@]}"
  run_shared_canary "$run_dir/shared-manifest.json"
fi

mkdir -p "$run_dir/canaries"
write_summary "$run_dir" "$run_env"
deploy_next_operators
write_summary "$run_dir" "$run_env"
if [[ "$paused_rehearsal" == "true" ]]; then
  log "rehearsal paused for resume proof: $run_dir"
else
  log "rehearsal complete: $run_dir"
fi
