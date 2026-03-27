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
  --shared-terraform-output-json PATH
                             Use a precomputed shared terraform output -json file
  --app-terraform-output-json PATH
                             Use a precomputed app runtime terraform output -json file
  --terraform-output-json PATH Deprecated alias for --shared-terraform-output-json
  --run-post-deploy-checks    Run role-based edge provisioning plus shared/app canaries
  --github-repo REPO          GitHub repo used for release asset resolution (default: juno-intents/intents-juno)
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
shared_terraform_output_json=""
app_terraform_output_json=""
run_post_deploy_checks="false"
github_repo="juno-intents/intents-juno"
skip_terraform_apply="false"
output_root="./production-output"
run_label=""
dry_run="false"
resolve_role_runtime_release_inputs_bin="${PRODUCTION_RESOLVE_ROLE_RUNTIME_RELEASE_INPUTS_BIN:-$SCRIPT_DIR/resolve-role-runtime-release-inputs.sh}"
refresh_app_runtime_bin="${PRODUCTION_REFRESH_APP_RUNTIME_BIN:-$SCRIPT_DIR/refresh-app-runtime.sh}"
provision_app_edge_bin="${PRODUCTION_PROVISION_APP_EDGE_BIN:-$SCRIPT_DIR/provision-app-edge.sh}"
canary_shared_bin="${PRODUCTION_CANARY_SHARED_BIN:-$SCRIPT_DIR/canary-shared-services.sh}"
canary_app_bin="${PRODUCTION_CANARY_APP_BIN:-$SCRIPT_DIR/canary-app-host.sh}"

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
    --shared-terraform-output-json) shared_terraform_output_json="$2"; shift 2 ;;
    --app-terraform-output-json) app_terraform_output_json="$2"; shift 2 ;;
    --terraform-output-json) shared_terraform_output_json="$2"; shift 2 ;;
    --run-post-deploy-checks) run_post_deploy_checks="true"; shift ;;
    --github-repo) github_repo="$2"; shift 2 ;;
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
if [[ "$run_post_deploy_checks" == "true" ]]; then
  for cmd in "$refresh_app_runtime_bin" "$provision_app_edge_bin" "$canary_shared_bin" "$canary_app_bin"; do
    have_cmd "$cmd" || [[ -x "$cmd" ]] || die "required command not found: $cmd"
  done
fi

inventory_dir="$(cd "$(dirname "$inventory")" && pwd)"
env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
shared_aws_region="$(production_json_required "$inventory" '.shared_services.aws_region | select(type == "string" and length > 0)')"
production_maybe_use_public_sts_endpoint "$shared_aws_region"
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
inventory_aws_profile="$(production_json_optional "$inventory" '.shared_services.aws_profile')"
inventory_aws_region="$(production_json_optional "$inventory" '.shared_services.aws_region')"
terraform_backend_account_id="$(production_json_optional "$inventory" '.shared_services.account_id')"
if [[ -z "$terraform_backend_account_id" ]]; then
  terraform_backend_account_id="$(production_json_optional "$inventory" '.app_role.account_id')"
fi
if [[ -z "$terraform_backend_account_id" ]]; then
  terraform_backend_account_id="$(production_json_optional "$inventory" '.operators[0].account_id')"
fi
shared_terraform_dir_rel="$(production_json_required "$inventory" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
shared_terraform_dir="$(production_abs_path "$REPO_ROOT" "$shared_terraform_dir_rel")"
[[ -d "$shared_terraform_dir" ]] || die "terraform dir not found: $shared_terraform_dir"
app_terraform_dir=""
app_terraform_dir_rel="$(production_json_optional "$inventory" '.app_role.terraform_dir | select(type == "string" and length > 0)')"
if [[ -n "$app_terraform_dir_rel" ]]; then
  app_terraform_dir="$(production_abs_path "$REPO_ROOT" "$app_terraform_dir_rel")"
  [[ -d "$app_terraform_dir" ]] || die "app terraform dir not found: $app_terraform_dir"
fi
shared_terraform_backend_bucket=""
shared_terraform_backend_table=""
shared_terraform_backend_key=""
shared_terraform_backend_args=()
shared_terraform_var_file=""
shared_tf_output_json=""
app_terraform_backend_bucket=""
app_terraform_backend_table=""
app_terraform_backend_key=""
app_terraform_backend_args=()
app_terraform_var_file=""
app_tf_output_json=""
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

role_runtime_release_resolution_required="$(
  jq -r '
    (
      (.app_role.ami_release_tag // "") != ""
      and (.app_role.app_ami_id // "") == ""
    )
    or (
      (.shared_roles.proof.image_release_tag // "") != ""
      and (
        (.shared_roles.proof.image_uri // "") == ""
        or (.shared_roles.proof.image_ecr_repository_arn // "") == ""
      )
    )
    or (
      (
        (.wireguard_role.ami_release_tag // "")
        // (.shared_roles.wireguard.ami_release_tag // "")
      ) != ""
      and (
        (
          (.wireguard_role.ami_id // "")
          // (.shared_roles.wireguard.ami_id // "")
        ) == ""
      )
    )
    | if . then "true" else "false" end
  ' "$coordinator_inventory"
)"
if [[ "$role_runtime_release_resolution_required" == "true" ]]; then
  have_cmd "$resolve_role_runtime_release_inputs_bin" || [[ -x "$resolve_role_runtime_release_inputs_bin" ]] || \
    die "required command not found: $resolve_role_runtime_release_inputs_bin"
  resolved_role_runtime_inventory="$output_dir/inventory.release-resolved.json"
  resolve_role_runtime_release_args=(
    "$resolve_role_runtime_release_inputs_bin"
    --inventory "$coordinator_inventory"
    --output "$resolved_role_runtime_inventory"
    --github-repo "$github_repo"
  )
  if [[ -n "$inventory_aws_profile" ]]; then
    resolve_role_runtime_release_args+=(--aws-profile "$inventory_aws_profile")
  fi
  if [[ -n "$inventory_aws_region" ]]; then
    resolve_role_runtime_release_args+=(--aws-region "$inventory_aws_region")
  fi
  "${resolve_role_runtime_release_args[@]}"
  coordinator_inventory="$resolved_role_runtime_inventory"
fi

min_deposit_admin_address=""
governance_safe_address=""
pause_guardian_address=""
if jq -e '.governance != null' "$inventory" >/dev/null 2>&1; then
  governance_safe_address="$(production_json_optional "$inventory" '.governance.safe')"
  pause_guardian_address="$(production_json_optional "$inventory" '.governance.pause_guardian')"
fi

if [[ "$skip_terraform_apply" != "true" || -z "$shared_terraform_output_json" ]]; then
  for cmd in terraform aws; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
  terraform_backend_output="$(
    production_bootstrap_terraform_backend "$inventory_aws_profile" "$inventory_aws_region" "$env_slug" "$shared_terraform_dir" "$terraform_backend_account_id"
  )" || die "failed to bootstrap terraform backend"
  mapfile -t terraform_backend_config <<<"$terraform_backend_output"
  (( ${#terraform_backend_config[@]} == 3 )) || die "terraform backend bootstrap returned incomplete configuration"
  shared_terraform_backend_bucket="${terraform_backend_config[0]}"
  shared_terraform_backend_table="${terraform_backend_config[1]}"
  shared_terraform_backend_key="${terraform_backend_config[2]}"
  shared_terraform_backend_args=(
    -reconfigure
    "-backend-config=bucket=$shared_terraform_backend_bucket"
    "-backend-config=dynamodb_table=$shared_terraform_backend_table"
    "-backend-config=key=$shared_terraform_backend_key"
    "-backend-config=region=$inventory_aws_region"
  )
fi

if [[ -n "$app_terraform_dir" && "$skip_terraform_apply" != "true" ]]; then
  for cmd in terraform aws; do
    have_cmd "$cmd" || die "required command not found: $cmd"
  done
  app_terraform_backend_output="$(
    production_bootstrap_terraform_backend "$inventory_aws_profile" "$inventory_aws_region" "$env_slug" "$app_terraform_dir" "$terraform_backend_account_id"
  )" || die "failed to bootstrap app terraform backend"
  mapfile -t app_terraform_backend_config <<<"$app_terraform_backend_output"
  (( ${#app_terraform_backend_config[@]} == 3 )) || die "app terraform backend bootstrap returned incomplete configuration"
  app_terraform_backend_bucket="${app_terraform_backend_config[0]}"
  app_terraform_backend_table="${app_terraform_backend_config[1]}"
  app_terraform_backend_key="${app_terraform_backend_config[2]}"
  app_terraform_backend_args=(
    -reconfigure
    "-backend-config=bucket=$app_terraform_backend_bucket"
    "-backend-config=dynamodb_table=$app_terraform_backend_table"
    "-backend-config=key=$app_terraform_backend_key"
    "-backend-config=region=$inventory_aws_region"
  )
fi

if [[ "$skip_terraform_apply" != "true" ]]; then
  shared_terraform_var_file="$output_dir/shared-terraform.auto.tfvars.json"
  production_write_shared_terraform_override_tfvars "$coordinator_inventory" "$shared_terraform_var_file"
  log "Applying shared-services terraform in $shared_terraform_dir"
  if [[ "$dry_run" != "true" ]]; then
    (
      cd "$shared_terraform_dir"
      terraform init -input=false "${shared_terraform_backend_args[@]}"
      if [[ -f "$shared_terraform_var_file" ]]; then
        terraform apply -auto-approve -input=false -var-file="$shared_terraform_var_file"
      else
        terraform apply -auto-approve -input=false
      fi
    )
  else
    log "[DRY RUN] skipped terraform apply"
  fi

  if [[ -n "$app_terraform_dir" ]]; then
    app_terraform_var_file="$output_dir/app-terraform.auto.tfvars.json"
    production_write_app_terraform_override_tfvars "$coordinator_inventory" "$app_terraform_var_file"
    log "Applying app runtime terraform in $app_terraform_dir"
    if [[ "$dry_run" != "true" ]]; then
      (
        cd "$app_terraform_dir"
        terraform init -input=false "${app_terraform_backend_args[@]}"
        if [[ -f "$app_terraform_var_file" ]]; then
          terraform apply -auto-approve -input=false -var-file="$app_terraform_var_file"
        else
          terraform apply -auto-approve -input=false
        fi
      )
    else
      log "[DRY RUN] skipped app runtime terraform apply"
    fi
  fi
fi

if [[ -n "$shared_terraform_output_json" ]]; then
  [[ -f "$shared_terraform_output_json" ]] || die "terraform output json not found: $shared_terraform_output_json"
  shared_tf_output_json="$output_dir/shared-terraform-output.json"
  cp "$shared_terraform_output_json" "$shared_tf_output_json"
else
  shared_tf_output_json="$output_dir/shared-terraform-output.json"
  (
    cd "$shared_terraform_dir"
    if [[ "$skip_terraform_apply" == "true" ]]; then
      terraform init -input=false "${shared_terraform_backend_args[@]}"
    fi
    terraform output -json >"$shared_tf_output_json"
  )
fi

if [[ -n "$app_terraform_output_json" ]]; then
  [[ -f "$app_terraform_output_json" ]] || die "app terraform output json not found: $app_terraform_output_json"
  app_tf_output_json="$output_dir/app-terraform-output.json"
  cp "$app_terraform_output_json" "$app_tf_output_json"
elif [[ -n "$app_terraform_dir" && "$skip_terraform_apply" != "true" ]]; then
  app_tf_output_json="$output_dir/app-terraform-output.json"
  (
    cd "$app_terraform_dir"
    terraform output -json >"$app_tf_output_json"
  )
fi

bridge_summary="$output_dir/bridge-summary.json"
if [[ -n "$existing_bridge_summary" ]]; then
  if [[ ! -e "$bridge_summary" || ! "$existing_bridge_summary" -ef "$bridge_summary" ]]; then
    cp "$existing_bridge_summary" "$bridge_summary"
  fi
else
  log "Deploying bridge contracts"
  bridge_deploy_name="$(basename "$bridge_deploy_binary")"
  bridge_deploy_name="$(sed -E 's/_(linux|darwin)_(amd64|arm64)$//' <<<"$bridge_deploy_name")"
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
    --withdrawal-expiry-window-seconds "$(production_default_bridge_withdrawal_expiry_window_seconds)" \
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
  production_run_release_binary "${bridge_deploy_cmd[@]}"
fi
production_refresh_bridge_summary_owallet_ua "$bridge_summary" "$dkg_summary" "$dkg_completion"

shared_manifest="$output_dir/shared-manifest.json"
production_render_shared_manifest "$coordinator_inventory" "$bridge_summary" "$dkg_summary" "$shared_tf_output_json" "$shared_manifest" "$inventory_dir" "$dkg_completion"
production_render_operator_handoffs "$coordinator_inventory" "$shared_manifest" "$dkg_summary" "$output_dir" "$inventory_dir"
if [[ -n "$generated_dkg_tls_dir" ]]; then
  production_rewrite_operator_handoffs_dkg_tls_dir "$output_dir" "$generated_dkg_tls_dir"
fi
production_render_app_handoff "$coordinator_inventory" "$shared_manifest" "$output_dir" "$inventory_dir" "$app_tf_output_json"

if [[ "$run_post_deploy_checks" == "true" ]]; then
  canary_output_dir="$output_dir/canaries"
  mkdir -p "$canary_output_dir"

  if [[ -f "$output_dir/app/app-deploy.json" ]]; then
    mkdir -p "$output_dir/app-runtime"
    post_deploy_refresh_app_args=(
      "$refresh_app_runtime_bin"
      --shared-manifest "$shared_manifest"
      --app-deploy "$output_dir/app/app-deploy.json"
      --output-dir "$output_dir/app-runtime"
    )
    if [[ "$dry_run" == "true" ]]; then
      post_deploy_refresh_app_args+=(--dry-run)
    fi
    "${post_deploy_refresh_app_args[@]}" >"$output_dir/app-runtime/refresh.json"
    [[ "$(jq -r '.ready_for_deploy' "$output_dir/app-runtime/refresh.json")" == "true" ]] || \
      die "app runtime refresh failed: $output_dir/app-runtime/refresh.json"

    post_deploy_app_args=("$provision_app_edge_bin" --app-deploy "$output_dir/app/app-deploy.json")
    if [[ "$dry_run" == "true" ]]; then
      post_deploy_app_args+=(--dry-run)
    fi
    "${post_deploy_app_args[@]}"
  fi

  post_deploy_shared_canary_args=("$canary_shared_bin" --shared-manifest "$shared_manifest")
  if [[ "$dry_run" == "true" ]]; then
    post_deploy_shared_canary_args+=(--dry-run)
  fi
  "${post_deploy_shared_canary_args[@]}" >"$canary_output_dir/shared-services.json"
  [[ "$(jq -r '.ready_for_deploy' "$canary_output_dir/shared-services.json")" == "true" ]] || \
    die "shared services canary failed: $canary_output_dir/shared-services.json"

  if [[ -f "$output_dir/app/app-deploy.json" ]]; then
    post_deploy_app_canary_args=("$canary_app_bin" --app-deploy "$output_dir/app/app-deploy.json")
    if [[ "$dry_run" == "true" ]]; then
      post_deploy_app_canary_args+=(--dry-run)
    fi
    "${post_deploy_app_canary_args[@]}" >"$canary_output_dir/app.json"
    [[ "$(jq -r '.ready_for_deploy' "$canary_output_dir/app.json")" == "true" ]] || \
      die "app canary failed: $canary_output_dir/app.json"
  fi
fi

log "shared manifest: $shared_manifest"
log "rollout state: $output_dir/rollout-state.json"
log "operator handoffs: $output_dir/operators"
if [[ -f "$output_dir/app/app-deploy.json" ]]; then
  log "app handoff: $output_dir/app/app-deploy.json"
fi
