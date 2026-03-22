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
  rebuild-preview-role-runtime.sh [options]

Options:
  --inventory PATH                             Preview inventory JSON (required)
  --dkg-summary PATH                           DKG summary JSON (required)
  --dkg-completion PATH                        Optional DKG completion JSON
  --bridge-deploy-binary PATH                  Released bridge-deploy binary (required unless reusing bridge)
  --deployer-key-file PATH                     Bridge deployer key file
  --funder-key-file PATH                       Bridge deploy ephemeral funder key
  --ephemeral-funding-amount-wei AMOUNT        Bridge deploy ephemeral funding amount
  --existing-bridge-summary PATH               Optional bridge summary reuse path
  --app-runtime-ami-release-tag TAG            Pinned app runtime AMI release tag (required)
  --shared-proof-services-image-release-tag TAG Pinned shared proof image release tag (required)
  --wireguard-role-ami-release-tag TAG         Pinned wireguard role AMI release tag (required)
  --operator-stack-ami-release-tag TAG         Pinned operator stack AMI release tag (required)
  --shared-infra-e2e-binary PATH               Released shared-infra-e2e binary (required)
  --github-repo REPO                           GitHub repo for release resolution (default: juno-intents/intents-juno)
  --output-dir DIR                             Output directory (default: ./preview-reset-output)
EOF
}

inventory=""
dkg_summary=""
dkg_completion=""
bridge_deploy_binary=""
deployer_key_file=""
funder_key_file=""
ephemeral_funding_amount_wei=""
existing_bridge_summary=""
app_runtime_ami_release_tag=""
shared_proof_services_image_release_tag=""
wireguard_role_ami_release_tag=""
operator_stack_ami_release_tag=""
shared_infra_e2e_binary=""
github_repo="juno-intents/intents-juno"
output_root="./preview-reset-output"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --inventory) inventory="$2"; shift 2 ;;
    --dkg-summary) dkg_summary="$2"; shift 2 ;;
    --dkg-completion) dkg_completion="$2"; shift 2 ;;
    --bridge-deploy-binary) bridge_deploy_binary="$2"; shift 2 ;;
    --deployer-key-file) deployer_key_file="$2"; shift 2 ;;
    --funder-key-file) funder_key_file="$2"; shift 2 ;;
    --ephemeral-funding-amount-wei) ephemeral_funding_amount_wei="$2"; shift 2 ;;
    --existing-bridge-summary) existing_bridge_summary="$2"; shift 2 ;;
    --app-runtime-ami-release-tag) app_runtime_ami_release_tag="$2"; shift 2 ;;
    --shared-proof-services-image-release-tag) shared_proof_services_image_release_tag="$2"; shift 2 ;;
    --wireguard-role-ami-release-tag) wireguard_role_ami_release_tag="$2"; shift 2 ;;
    --operator-stack-ami-release-tag) operator_stack_ami_release_tag="$2"; shift 2 ;;
    --shared-infra-e2e-binary) shared_infra_e2e_binary="$2"; shift 2 ;;
    --github-repo) github_repo="$2"; shift 2 ;;
    --output-dir) output_root="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

normalize_preview_inventory_local_paths() {
  local source_inventory="$1"
  local target_inventory="$2"
  local source_inventory_dir tmp_inventory

  source_inventory_dir="$(dirname "$(production_abs_path "$(pwd)" "$source_inventory")")"
  tmp_inventory="$(mktemp)"
  jq --arg source_inventory_dir "$source_inventory_dir" '
    def abs_source_path:
      if type == "string" and length > 0 then
        if startswith("/") then . else ($source_inventory_dir + "/" + .) end
      else .
      end;
    .dkg_tls_dir |= (if . == null then . else abs_source_path end)
    | if .app_role != null then
        .app_role.known_hosts_file |= (if . == null then . else abs_source_path end)
        | .app_role.secret_contract_file |= (if . == null then . else abs_source_path end)
      else .
      end
    | if .app_host != null then
        .app_host.known_hosts_file |= (if . == null then . else abs_source_path end)
        | .app_host.secret_contract_file |= (if . == null then . else abs_source_path end)
      else .
      end
    | .operators = (
        (.operators // [])
        | map(
            .known_hosts_file |= (if . == null then . else abs_source_path end)
            | .secret_contract_file |= (if . == null then . else abs_source_path end)
            | .dkg_backup_zip |= (if . == null then . else abs_source_path end)
          )
      )
  ' "$target_inventory" >"$tmp_inventory"
  mv "$tmp_inventory" "$target_inventory"
}

[[ -n "$inventory" ]] || die "--inventory is required"
[[ -f "$inventory" ]] || die "inventory not found: $inventory"
[[ -n "$dkg_summary" ]] || die "--dkg-summary is required"
[[ -f "$dkg_summary" ]] || die "dkg summary not found: $dkg_summary"
[[ -n "$app_runtime_ami_release_tag" ]] || die "--app-runtime-ami-release-tag is required"
[[ -n "$shared_proof_services_image_release_tag" ]] || die "--shared-proof-services-image-release-tag is required"
[[ -n "$wireguard_role_ami_release_tag" ]] || die "--wireguard-role-ami-release-tag is required"
[[ -n "$operator_stack_ami_release_tag" ]] || die "--operator-stack-ami-release-tag is required"
[[ -n "$shared_infra_e2e_binary" ]] || die "--shared-infra-e2e-binary is required"
[[ -f "$shared_infra_e2e_binary" ]] || die "shared-infra-e2e binary not found: $shared_infra_e2e_binary"

upgrade_preview_inventory_bin="${PRODUCTION_UPGRADE_PREVIEW_INVENTORY_BIN:-$SCRIPT_DIR/upgrade-preview-inventory.sh}"
destroy_preview_role_runtime_bin="${PRODUCTION_DESTROY_PREVIEW_ROLE_RUNTIME_BIN:-$SCRIPT_DIR/destroy-preview-role-runtime.sh}"
resolve_role_runtime_release_inputs_bin="${PRODUCTION_RESOLVE_ROLE_RUNTIME_RELEASE_INPUTS_BIN:-$SCRIPT_DIR/resolve-role-runtime-release-inputs.sh}"
deploy_coordinator_bin="${PRODUCTION_DEPLOY_COORDINATOR_BIN:-$SCRIPT_DIR/deploy-coordinator.sh}"
provision_app_edge_bin="${PRODUCTION_PROVISION_APP_EDGE_BIN:-$SCRIPT_DIR/provision-app-edge.sh}"
canary_shared_bin="${PRODUCTION_CANARY_SHARED_BIN:-$SCRIPT_DIR/canary-shared-services.sh}"
refresh_app_runtime_bin="${PRODUCTION_REFRESH_APP_RUNTIME_BIN:-$SCRIPT_DIR/refresh-app-runtime.sh}"
canary_app_bin="${PRODUCTION_CANARY_APP_BIN:-$SCRIPT_DIR/canary-app-host.sh}"
roll_preview_operators_bin="${PRODUCTION_ROLL_PREVIEW_OPERATORS_BIN:-$SCRIPT_DIR/roll-preview-operators.sh}"
refresh_preview_app_backoffice_bin="${PRODUCTION_REFRESH_PREVIEW_APP_BACKOFFICE_BIN:-$SCRIPT_DIR/refresh-preview-app-backoffice.sh}"
refresh_preview_wireguard_backoffice_bin="${PRODUCTION_REFRESH_PREVIEW_WIREGUARD_BACKOFFICE_BIN:-$SCRIPT_DIR/refresh-preview-wireguard-backoffice.sh}"

for cmd in \
  "$upgrade_preview_inventory_bin" \
  "$destroy_preview_role_runtime_bin" \
  "$resolve_role_runtime_release_inputs_bin" \
  "$deploy_coordinator_bin" \
  "$provision_app_edge_bin" \
  "$canary_shared_bin" \
  "$refresh_app_runtime_bin" \
  "$canary_app_bin" \
  "$roll_preview_operators_bin" \
  "$refresh_preview_app_backoffice_bin" \
  "$refresh_preview_wireguard_backoffice_bin"; do
  [[ -x "$cmd" ]] || have_cmd "$cmd" || die "required command not found: $cmd"
done

env_slug="$(production_json_required "$inventory" '.environment | select(type == "string" and length > 0)')"
output_dir="$output_root/$env_slug"
mkdir -p "$output_dir/canaries" "$output_dir/e2e"

upgraded_inventory="$output_dir/inventory.preview-runtime.json"
resolved_inventory="$output_dir/inventory.resolved.json"
current_output_root="$(dirname "$(production_abs_path "$(pwd)" "$inventory")")/production-output"
current_shared_tf_output="$current_output_root/$env_slug/shared-terraform-output.json"

"$upgrade_preview_inventory_bin" \
  --inventory "$inventory" \
  --output "$upgraded_inventory" \
  --app-runtime-ami-release-tag "$app_runtime_ami_release_tag" \
  --shared-proof-services-image-release-tag "$shared_proof_services_image_release_tag" \
  --wireguard-role-ami-release-tag "$wireguard_role_ami_release_tag"

"$resolve_role_runtime_release_inputs_bin" \
  --inventory "$upgraded_inventory" \
  --output "$resolved_inventory" \
  --github-repo "$github_repo"

if [[ -f "$current_shared_tf_output" ]]; then
  tmp_inventory="$(mktemp)"
  jq \
    --arg requestor_secret_arn "$(jq -r '.shared_proof_requestor_secret_arn.value // empty' "$current_shared_tf_output")" \
    --arg funder_secret_arn "$(jq -r '.shared_proof_funder_secret_arn.value // empty' "$current_shared_tf_output")" \
    --arg requestor_address "$(jq -r '.shared_sp1_requestor_address.value // empty' "$current_shared_tf_output")" \
    --arg rpc_url "$(jq -r '.shared_sp1_rpc_url.value // empty' "$current_shared_tf_output")" \
    '
      .shared_roles = (.shared_roles // {})
      | .shared_roles.proof = (.shared_roles.proof // {})
      | if (.shared_roles.proof.requestor_secret_arn // "") == "" and $requestor_secret_arn != "" then
          .shared_roles.proof.requestor_secret_arn = $requestor_secret_arn
        else .
        end
      | if (.shared_roles.proof.funder_secret_arn // "") == "" and $funder_secret_arn != "" then
          .shared_roles.proof.funder_secret_arn = $funder_secret_arn
        else .
        end
      | if (.shared_roles.proof.requestor_address // "") == "" and $requestor_address != "" then
          .shared_roles.proof.requestor_address = $requestor_address
        else .
        end
      | if (.shared_roles.proof.rpc_url // "") == "" and $rpc_url != "" then
          .shared_roles.proof.rpc_url = $rpc_url
        else .
        end
    ' "$resolved_inventory" >"$tmp_inventory"
  mv "$tmp_inventory" "$resolved_inventory"
fi

normalize_preview_inventory_local_paths "$inventory" "$resolved_inventory"

"$destroy_preview_role_runtime_bin" \
  --inventory "$resolved_inventory" \
  --current-output-root "$current_output_root" \
  --skip-missing-edge-state

coordinator_args=(
  "$deploy_coordinator_bin"
  --inventory "$resolved_inventory"
  --dkg-summary "$dkg_summary"
  --bridge-deploy-binary "$bridge_deploy_binary"
  --output-dir "$output_root"
  --github-repo "$github_repo"
)
if [[ -n "$dkg_completion" ]]; then
  coordinator_args+=(--dkg-completion "$dkg_completion")
fi
if [[ -n "$existing_bridge_summary" ]]; then
  coordinator_args+=(--existing-bridge-summary "$existing_bridge_summary")
fi
if [[ -n "$deployer_key_file" ]]; then
  coordinator_args+=(--deployer-key-file "$deployer_key_file")
fi
if [[ -n "$funder_key_file" ]]; then
  coordinator_args+=(--funder-key-file "$funder_key_file")
fi
if [[ -n "$ephemeral_funding_amount_wei" ]]; then
  coordinator_args+=(--ephemeral-funding-amount-wei "$ephemeral_funding_amount_wei")
fi
"${coordinator_args[@]}"

app_deploy="$output_root/$env_slug/app/app-deploy.json"
shared_manifest="$output_root/$env_slug/shared-manifest.json"
bridge_summary_path="$output_root/$env_slug/bridge-summary.json"
[[ -f "$app_deploy" ]] || die "rebuilt preview app deploy manifest not found: $app_deploy"
[[ -f "$shared_manifest" ]] || die "rebuilt preview shared manifest not found: $shared_manifest"
[[ -f "$bridge_summary_path" ]] || die "rebuilt preview bridge summary not found: $bridge_summary_path"

"$provision_app_edge_bin" --app-deploy "$app_deploy"
"$canary_shared_bin" --shared-manifest "$shared_manifest" >"$output_dir/canaries/shared-services.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/canaries/shared-services.json")" == "true" ]] || die "shared services canary failed"
app_runtime_refresh_path="$output_dir/app-runtime-refresh.json"
"$refresh_app_runtime_bin" \
  --shared-manifest "$shared_manifest" \
  --app-deploy "$app_deploy" \
  --output-dir "$output_dir/app-runtime" >"$app_runtime_refresh_path"
[[ "$(jq -r '.ready_for_deploy' "$app_runtime_refresh_path")" == "true" ]] || die "app runtime refresh failed"
"$canary_app_bin" --app-deploy "$app_deploy" >"$output_dir/canaries/app.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/canaries/app.json")" == "true" ]] || die "app canary failed"

resolved_env="$(mktemp)"
trap 'rm -f "$resolved_env"' EXIT
aws_profile="$(jq -r '.aws_profile // empty' "$app_deploy")"
aws_region="$(jq -r '.aws_region // empty' "$app_deploy")"
allow_local_resolvers="false"
if production_environment_allows_local_secret_resolvers "$env_slug"; then
  allow_local_resolvers="true"
fi
production_resolve_secret_contract "$(jq -r '.secret_contract_file' "$app_deploy")" "$allow_local_resolvers" "$aws_profile" "$aws_region" "$resolved_env"
checkpoint_postgres_dsn="$(production_env_first_value "$resolved_env" CHECKPOINT_POSTGRES_DSN APP_POSTGRES_DSN)"
kafka_brokers="$(jq -r '.shared_services.kafka.bootstrap_brokers' "$shared_manifest")"
ipfs_api_url="$(jq -r '.shared_services.ipfs.api_url' "$shared_manifest")"
checkpoint_operators="$(jq -r '.checkpoint.operators | join(",")' "$shared_manifest")"
checkpoint_threshold="$(jq -r '.checkpoint.threshold' "$shared_manifest")"
checkpoint_topics="$(jq -r '.checkpoint.signature_topic + "," + .checkpoint.package_topic' "$shared_manifest")"
operator_topics="deposits.event.v2,withdrawals.requested.v2"
required_topics="proof.requests.v1,proof.fulfillments.v1,proof.failures.v1,ops.alerts.v1,${checkpoint_topics},${operator_topics}"
production_run_release_binary "$shared_infra_e2e_binary" \
  --postgres-dsn "$checkpoint_postgres_dsn" \
  --kafka-brokers "$kafka_brokers" \
  --required-kafka-topics "$required_topics" \
  --checkpoint-ipfs-api-url "$ipfs_api_url" \
  --checkpoint-operators "$checkpoint_operators" \
  --checkpoint-threshold "$checkpoint_threshold" \
  --output "$output_dir/e2e/shared-infra-e2e.json"

"$roll_preview_operators_bin" \
  --inventory "$resolved_inventory" \
  --shared-manifest "$shared_manifest" \
  --dkg-summary "$dkg_summary" \
  --operator-stack-ami-release-tag "$operator_stack_ami_release_tag" \
  --output-dir "$output_dir/operator-rollout" \
  --github-repo "$github_repo" >"$output_dir/operator-rollout.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/operator-rollout.json")" == "true" ]] || die "operator rollout failed"

first_operator_deploy="$(find "$output_dir/operator-rollout/operators" -name operator-deploy.json | sort | head -n1)"
[[ -n "$first_operator_deploy" ]] || die "operator rollout did not render any operator deploy handoffs"

wireguard_backoffice_refresh_path="$output_dir/wireguard-backoffice.json"
wireguard_backoffice_args=(
  "$refresh_preview_wireguard_backoffice_bin"
  --inventory "$resolved_inventory" \
  --bridge-summary "$bridge_summary_path" \
  --dkg-summary "$dkg_summary" \
  --app-deploy "$app_deploy" \
  --shared-manifest "$shared_manifest" \
  --operator-deploy "$first_operator_deploy" \
  --output-dir "$output_dir/wireguard-backoffice"
)
if [[ -n "$dkg_completion" ]]; then
  wireguard_backoffice_args+=(--dkg-completion "$dkg_completion")
fi
"${wireguard_backoffice_args[@]}" >"$wireguard_backoffice_refresh_path"
[[ "$(jq -r '.ready_for_deploy' "$wireguard_backoffice_refresh_path")" == "true" ]] || die "wireguard backoffice refresh failed"
"$canary_shared_bin" --shared-manifest "$shared_manifest" >"$output_dir/canaries/shared-services.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/canaries/shared-services.json")" == "true" ]] || die "shared services canary failed after wireguard backoffice refresh"

"$refresh_preview_app_backoffice_bin" \
  --rolled-inventory "$output_dir/operator-rollout/inventory.operators-rolled.json" \
  --shared-manifest "$shared_manifest" \
  --app-deploy "$app_deploy" \
  --output-dir "$output_dir/operator-rollout" >"$output_dir/app-backoffice-refresh.json"
[[ "$(jq -r '.ready_for_deploy' "$output_dir/app-backoffice-refresh.json")" == "true" ]] || die "preview app backoffice refresh failed"

release_lock="$output_dir/role-runtime-release-lock.json"
jq -n \
  --arg workflow "reset-preview-role-runtime" \
  --arg inventory_path "$inventory" \
  --arg app_runtime_ami_release_tag "$app_runtime_ami_release_tag" \
  --arg shared_proof_services_image_release_tag "$shared_proof_services_image_release_tag" \
  --arg wireguard_role_ami_release_tag "$wireguard_role_ami_release_tag" \
  --arg operator_stack_ami_release_tag "$operator_stack_ami_release_tag" \
  --arg shared_manifest "$shared_manifest" \
  --arg app_deploy "$app_deploy" \
  --arg bridge_summary_path "$bridge_summary_path" \
  --arg operator_rollout_path "$output_dir/operator-rollout.json" \
  --arg app_runtime_refresh_path "$app_runtime_refresh_path" \
  --arg wireguard_backoffice_refresh_path "$wireguard_backoffice_refresh_path" \
  --arg app_backoffice_refresh_path "$output_dir/app-backoffice-refresh.json" \
  --arg preview_completed_at "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" '
    {
      workflow: $workflow,
      inventory_path: $inventory_path,
      app_runtime_ami_release_tag: $app_runtime_ami_release_tag,
      shared_proof_services_image_release_tag: $shared_proof_services_image_release_tag,
      wireguard_role_ami_release_tag: $wireguard_role_ami_release_tag,
      operator_stack_ami_release_tag: $operator_stack_ami_release_tag,
      shared_manifest: $shared_manifest,
      app_deploy: $app_deploy,
      bridge_summary_path: $bridge_summary_path,
      operator_rollout_path: $operator_rollout_path,
      app_runtime_refresh_path: $app_runtime_refresh_path,
      wireguard_backoffice_refresh_path: $wireguard_backoffice_refresh_path,
      app_backoffice_refresh_path: $app_backoffice_refresh_path,
      preview_completed_at: $preview_completed_at
    }
  ' >"$release_lock"
