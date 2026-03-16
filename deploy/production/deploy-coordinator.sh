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
  deploy-coordinator.sh [options]

Options:
  --inventory PATH             Deployment inventory JSON (required)
  --dkg-summary PATH           DKG summary JSON (required)
  --dkg-completion PATH        Optional DKG completion JSON for UFVK/Juno address fallback
  --bridge-deploy-binary PATH  Bridge deploy binary (required unless reusing bridge summary)
  --deployer-key-file PATH     Deployer key file (required when deploying bridge)
  --funder-key-file PATH       Funder key file for bridge-deploy ephemeral mode
  --ephemeral-funding-amount-wei AMOUNT
                               Wei amount to fund a generated ephemeral deployer
  --sweep-recipient ADDRESS    Optional sweep recipient for the ephemeral deployer
  --existing-bridge-summary PATH
                               Reuse an existing bridge summary instead of deploying
  --terraform-output-json PATH Use a precomputed terraform output -json file
  --skip-terraform-apply       Do not run terraform init/apply
  --output-dir DIR             Output root (default: ./production-output)
  --run-label LABEL            Optional subdirectory under <output-dir>/<environment> (example: run-20260311T120000Z)
  --dry-run                    Skip external mutations; requires existing bridge summary
EOF
}

inventory=""
dkg_summary=""
dkg_completion=""
bridge_deploy_binary=""
deployer_key_file=""
funder_key_file=""
ephemeral_funding_amount_wei=""
sweep_recipient=""
existing_bridge_summary=""
terraform_output_json=""
skip_terraform_apply="false"
output_root="./production-output"
run_label=""
dry_run="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory) inventory="$2"; shift 2 ;;
    --dkg-summary) dkg_summary="$2"; shift 2 ;;
    --dkg-completion) dkg_completion="$2"; shift 2 ;;
    --bridge-deploy-binary) bridge_deploy_binary="$2"; shift 2 ;;
    --deployer-key-file) deployer_key_file="$2"; shift 2 ;;
    --funder-key-file) funder_key_file="$2"; shift 2 ;;
    --ephemeral-funding-amount-wei) ephemeral_funding_amount_wei="$2"; shift 2 ;;
    --sweep-recipient) sweep_recipient="$2"; shift 2 ;;
    --existing-bridge-summary) existing_bridge_summary="$2"; shift 2 ;;
    --terraform-output-json) terraform_output_json="$2"; shift 2 ;;
    --skip-terraform-apply) skip_terraform_apply="true"; shift ;;
    --output-dir) output_root="$2"; shift 2 ;;
    --run-label) run_label="$2"; shift 2 ;;
    --dry-run) dry_run="true"; shift ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$inventory" ]] || die "--inventory is required"
[[ -f "$inventory" ]] || die "inventory not found: $inventory"
[[ -n "$dkg_summary" ]] || die "--dkg-summary is required"
[[ -f "$dkg_summary" ]] || die "dkg summary not found: $dkg_summary"
if [[ -n "$dkg_completion" ]]; then
  [[ -f "$dkg_completion" ]] || die "dkg completion not found: $dkg_completion"
fi
if [[ -z "$existing_bridge_summary" ]]; then
  [[ -n "$bridge_deploy_binary" ]] || die "--bridge-deploy-binary is required when bridge summary is not reused"
  [[ -f "$bridge_deploy_binary" ]] || die "bridge deploy binary not found: $bridge_deploy_binary"
  [[ "$dry_run" != "true" ]] || die "--dry-run requires --existing-bridge-summary"
  if [[ -n "$deployer_key_file" ]]; then
    [[ -f "$deployer_key_file" ]] || die "deployer key file not found: $deployer_key_file"
  fi
  if [[ -n "$funder_key_file" ]]; then
    [[ -f "$funder_key_file" ]] || die "funder key file not found: $funder_key_file"
  fi
else
  [[ -f "$existing_bridge_summary" ]] || die "bridge summary not found: $existing_bridge_summary"
fi

for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

inventory_dir="$(cd "$(dirname "$inventory")" && pwd)"
env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
coordinator_inventory="$inventory"
generated_dkg_tls_dir=""
if [[ -z "$existing_bridge_summary" ]]; then
  if [[ -n "$deployer_key_file" && -n "$funder_key_file" ]]; then
    die "use only one of --deployer-key-file or --funder-key-file"
  fi
  if [[ -n "$sweep_recipient" && -z "$funder_key_file" ]]; then
    die "--sweep-recipient requires --funder-key-file"
  fi
  if [[ "$env_slug" == "alpha" ]]; then
    if [[ -z "$deployer_key_file" && -z "$funder_key_file" ]]; then
      die "--deployer-key-file or --funder-key-file is required when deploying bridge"
    fi
  else
    [[ -z "$deployer_key_file" ]] || die "--deployer-key-file is not allowed outside alpha; use --funder-key-file with bridge-deploy ephemeral mode"
    [[ -n "$funder_key_file" ]] || die "--funder-key-file is required when deploying bridge outside alpha"
    [[ -n "$ephemeral_funding_amount_wei" ]] || die "--ephemeral-funding-amount-wei is required when deploying bridge outside alpha"
  fi
  if [[ -n "$funder_key_file" && -z "$ephemeral_funding_amount_wei" ]]; then
    die "--ephemeral-funding-amount-wei is required with --funder-key-file"
  fi
  if [[ -n "$deployer_key_file" && -n "$ephemeral_funding_amount_wei" ]]; then
    die "--ephemeral-funding-amount-wei requires --funder-key-file"
  fi
fi
base_rpc_url="$(production_json_required "$inventory" '.contracts.base_rpc_url | select(type == "string" and length > 0)')"
base_chain_id="$(production_json_required "$inventory" '.contracts.base_chain_id')"
deposit_image_id="$(production_json_required "$inventory" '.contracts.deposit_image_id | select(type == "string" and length > 0)')"
withdraw_image_id="$(production_json_required "$inventory" '.contracts.withdraw_image_id | select(type == "string" and length > 0)')"
bridge_verifier_address="$(production_bridge_verifier_address "$inventory")"
bridge_threshold="$(production_threshold "$dkg_summary")"
allow_local_resolvers="false"
if production_environment_allows_local_secret_resolvers "$env_slug"; then
  allow_local_resolvers="true"
fi
inventory_aws_profile="$(production_json_optional "$inventory" '.shared_services.aws_profile')"
inventory_aws_region="$(production_json_optional "$inventory" '.shared_services.aws_region')"
terraform_dir_rel="$(production_json_required "$inventory" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
terraform_dir="$(production_abs_path "$REPO_ROOT" "$terraform_dir_rel")"
[[ -d "$terraform_dir" ]] || die "terraform dir not found: $terraform_dir"
if [[ -n "$run_label" ]]; then
  output_dir="$output_root/$env_slug/$(production_safe_slug "$run_label")"
else
  output_dir="$output_root/$env_slug"
fi
mkdir -p "$output_dir"

if [[ -z "$(production_json_optional "$inventory" '.dkg_tls_dir | select(type == "string" and length > 0)')" ]]; then
  generated_dkg_tls_dir="$output_dir/dkg-tls"
  production_generate_dkg_tls_bundle "$generated_dkg_tls_dir"
  coordinator_inventory="$output_dir/inventory.render.json"
  jq --arg dkg_tls_dir "$generated_dkg_tls_dir" '.dkg_tls_dir = $dkg_tls_dir' "$inventory" >"$coordinator_inventory"
fi

minimum_base_relayer_balance_wei="$(production_required_min_base_relayer_balance_wei)"
preflight_secret_dir="$(mktemp -d)"
trap 'rm -rf "$preflight_secret_dir"' EXIT
while IFS= read -r operator_json; do
  operator_id="$(jq -r '.operator_id | select(type == "string" and length > 0)' <<<"$operator_json")"
  secret_contract_rel="$(jq -r '.secret_contract_file | select(type == "string" and length > 0)' <<<"$operator_json")"
  secret_contract_file="$(production_abs_path "$inventory_dir" "$secret_contract_rel")"
  [[ -f "$secret_contract_file" ]] || die "operator secret contract file not found: $secret_contract_file"
  resolved_secret_env="$preflight_secret_dir/${operator_id}.env"
  production_resolve_secret_contract "$secret_contract_file" "$allow_local_resolvers" "$inventory_aws_profile" "$inventory_aws_region" "$resolved_secret_env"
  production_require_base_relayer_balance "$resolved_secret_env" "$base_rpc_url" "$minimum_base_relayer_balance_wei"
done < <(jq -c '.operators[]' "$inventory")

min_deposit_admin_address=""
governance_safe_address=""
pause_guardian_address=""
if jq -e '.app_host != null' "$inventory" >/dev/null 2>&1; then
  app_secret_contract_rel="$(jq -r '.app_host.secret_contract_file | select(type == "string" and length > 0)' "$inventory")"
  app_secret_contract_file="$(production_abs_path "$inventory_dir" "$app_secret_contract_rel")"
  [[ -f "$app_secret_contract_file" ]] || die "app secret contract file not found: $app_secret_contract_file"
  resolved_app_secret_env="$preflight_secret_dir/app.env"
  production_resolve_secret_contract "$app_secret_contract_file" "$allow_local_resolvers" "$inventory_aws_profile" "$inventory_aws_region" "$resolved_app_secret_env"
  min_deposit_admin_private_key="$(production_env_first_value "$resolved_app_secret_env" MIN_DEPOSIT_ADMIN_PRIVATE_KEY APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY || true)"
  [[ -n "$min_deposit_admin_private_key" ]] || die "app secret contract is missing MIN_DEPOSIT_ADMIN_PRIVATE_KEY or APP_MIN_DEPOSIT_ADMIN_PRIVATE_KEY"
  min_deposit_admin_private_key="$(trim "$min_deposit_admin_private_key")"
  [[ "$min_deposit_admin_private_key" != *,* ]] || die "app min deposit admin secret must contain exactly one private key"
  min_deposit_admin_address="$(cast wallet address --private-key "$min_deposit_admin_private_key" | tr -d '[:space:]')"
  [[ "$min_deposit_admin_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "derived min deposit admin address is invalid: $min_deposit_admin_address"
fi
if jq -e '.governance != null' "$inventory" >/dev/null 2>&1; then
  governance_safe_address="$(production_json_optional "$inventory" '.governance.safe')"
  pause_guardian_address="$(production_json_optional "$inventory" '.governance.pause_guardian')"
fi

if [[ "$skip_terraform_apply" != "true" ]]; then
  for cmd in terraform; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
  log "Applying shared-services terraform in $terraform_dir"
  if [[ "$dry_run" != "true" ]]; then
    (
      cd "$terraform_dir"
      terraform init -input=false
      terraform apply -auto-approve -input=false
    )
  else
    log "[DRY RUN] skipped terraform apply"
  fi
fi

if [[ -n "$terraform_output_json" ]]; then
  [[ -f "$terraform_output_json" ]] || die "terraform output json not found: $terraform_output_json"
  tf_output_json="$output_dir/terraform-output.json"
  cp "$terraform_output_json" "$tf_output_json"
else
  for cmd in terraform; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
  tf_output_json="$output_dir/terraform-output.json"
  (
    cd "$terraform_dir"
    terraform output -json >"$tf_output_json"
  )
fi

bridge_summary="$output_dir/bridge-summary.json"
if [[ -n "$existing_bridge_summary" ]]; then
  cp "$existing_bridge_summary" "$bridge_summary"
else
  log "Deploying bridge contracts"
  bridge_deploy_name="$(basename "$bridge_deploy_binary")"
  [[ "$bridge_deploy_name" == "bridge-deploy" ]] || die "production bridge deployment requires a bridge-deploy binary, got: $bridge_deploy_name"
  bridge_deploy_cmd=(
    "$bridge_deploy_binary"
    --rpc-url "$base_rpc_url" \
    --chain-id "$base_chain_id" \
    --contracts-out "$REPO_ROOT/contracts/out" \
    --threshold "$bridge_threshold" \
    --verifier-address "$bridge_verifier_address" \
    --deposit-image-id "$deposit_image_id" \
    --withdraw-image-id "$withdraw_image_id" \
    --fee-bps "$(production_default_bridge_fee_bps)" \
    --relayer-tip-bps "$(production_default_bridge_relayer_tip_bps)" \
    --refund-window-seconds "$(production_default_bridge_refund_window_seconds)" \
    --max-expiry-extension-seconds "$(production_default_bridge_max_expiry_extension_seconds)" \
    --min-deposit-amount "$(production_default_bridge_min_deposit_amount_zat)" \
    --min-withdraw-amount "$(production_default_bridge_min_withdraw_amount_zat)" \
    --output "$bridge_summary"
  )
  if [[ -n "$funder_key_file" ]]; then
    bridge_deploy_cmd+=(--funder-key-file "$funder_key_file" --ephemeral-funding-amount-wei "$ephemeral_funding_amount_wei")
    if [[ -n "$sweep_recipient" ]]; then
      bridge_deploy_cmd+=(--sweep-recipient "$sweep_recipient")
    fi
  else
    bridge_deploy_cmd+=(--deployer-key-file "$deployer_key_file")
  fi
  [[ -n "$governance_safe_address" ]] || die "inventory is missing governance.safe required by bridge-deploy"
  [[ -n "$pause_guardian_address" ]] || die "inventory is missing governance.pause_guardian required by bridge-deploy"
  bridge_deploy_cmd+=(--governance-safe "$governance_safe_address" --pause-guardian "$pause_guardian_address")
  while IFS= read -r operator_address; do
    [[ -n "$operator_address" ]] || continue
    bridge_deploy_cmd+=(--operator-address "$operator_address")
  done < <(jq -r '.operators[].operator_id | select(type == "string" and length > 0)' "$dkg_summary")
  if [[ -n "$min_deposit_admin_address" ]]; then
    bridge_deploy_cmd+=(--min-deposit-admin-address "$min_deposit_admin_address")
  fi
  "${bridge_deploy_cmd[@]}"
fi
production_refresh_bridge_summary_owallet_ua "$bridge_summary" "$dkg_summary" "$dkg_completion"

shared_manifest="$output_dir/shared-manifest.json"
production_render_shared_manifest "$coordinator_inventory" "$bridge_summary" "$dkg_summary" "$tf_output_json" "$shared_manifest" "$inventory_dir" "$dkg_completion"
production_render_operator_handoffs "$coordinator_inventory" "$shared_manifest" "$dkg_summary" "$output_dir" "$inventory_dir"
if [[ -n "$generated_dkg_tls_dir" ]]; then
  production_rewrite_operator_handoffs_dkg_tls_dir "$output_dir" "$generated_dkg_tls_dir"
fi
production_render_app_handoff "$coordinator_inventory" "$shared_manifest" "$output_dir" "$inventory_dir"

log "shared manifest: $shared_manifest"
log "rollout state: $output_dir/rollout-state.json"
log "operator handoffs: $output_dir/operators"
if [[ -f "$output_dir/app/app-deploy.json" ]]; then
  log "app handoff: $output_dir/app/app-deploy.json"
fi
