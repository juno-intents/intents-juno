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
  [[ -n "$deployer_key_file" ]] || die "--deployer-key-file is required when deploying bridge"
  [[ -f "$deployer_key_file" ]] || die "deployer key file not found: $deployer_key_file"
else
  [[ -f "$existing_bridge_summary" ]] || die "bridge summary not found: $existing_bridge_summary"
fi

for cmd in jq; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

inventory_dir="$(cd "$(dirname "$inventory")" && pwd)"
env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
terraform_dir_rel="$(production_json_required "$inventory" '.shared_services.terraform_dir | select(type == "string" and length > 0)')"
terraform_dir="$(production_abs_path "$REPO_ROOT" "$terraform_dir_rel")"
[[ -d "$terraform_dir" ]] || die "terraform dir not found: $terraform_dir"
if [[ -n "$run_label" ]]; then
  output_dir="$output_root/$env_slug/$(production_safe_slug "$run_label")"
else
  output_dir="$output_root/$env_slug"
fi
mkdir -p "$output_dir"

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
  "$bridge_deploy_binary" deploy \
    --rpc-url "$(production_json_required "$inventory" '.contracts.base_rpc_url | select(type == "string" and length > 0)')" \
    --chain-id "$(production_json_required "$inventory" '.contracts.base_chain_id')" \
    --deployer-key-file "$deployer_key_file" \
    --dkg-summary "$dkg_summary" \
    --output "$bridge_summary"
fi

shared_manifest="$output_dir/shared-manifest.json"
production_render_shared_manifest "$inventory" "$bridge_summary" "$dkg_summary" "$tf_output_json" "$shared_manifest" "$inventory_dir" "$dkg_completion"
production_render_operator_handoffs "$inventory" "$shared_manifest" "$dkg_summary" "$output_dir" "$inventory_dir"
production_render_app_handoff "$inventory" "$shared_manifest" "$output_dir" "$inventory_dir"

log "shared manifest: $shared_manifest"
log "rollout state: $output_dir/rollout-state.json"
log "operator handoffs: $output_dir/operators"
if [[ -f "$output_dir/app/app-deploy.json" ]]; then
  log "app handoff: $output_dir/app/app-deploy.json"
fi
