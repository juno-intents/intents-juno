#!/usr/bin/env bash
# shellcheck shell=bash
#
# deploy-coordinator.sh — Deploy shared infrastructure and bridge contracts for
# a production Juno Bridge coordinator.
#
# Usage:
#   deploy-coordinator.sh [options]
#
# Options:
#   --terraform-dir DIR      Path to Terraform live directory (required)
#   --bridge-deploy-binary   Path to bridge-deploy binary (required)
#   --dkg-summary PATH       Path to DKG summary JSON (required)
#   --base-rpc-url URL       Base chain RPC URL (required)
#   --base-chain-id ID       Base chain ID (required)
#   --deployer-key-file PATH Private key file for contract deployer (required)
#   --output-dir DIR         Output directory for shared-config.json (default: ./production-output)
#   --existing-bridge-summary PATH  Reuse existing bridge contracts (skip deploy)
#   --aws-profile PROFILE    AWS CLI profile (default: juno)
#   --dry-run                Print actions without executing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# shellcheck source=../operators/dkg/common.sh
source "$REPO_ROOT/deploy/operators/dkg/common.sh"

# ── Defaults ──────────────────────────────────────────────────────────────────
terraform_dir=""
bridge_deploy_binary=""
dkg_summary=""
base_rpc_url=""
base_chain_id=""
deployer_key_file=""
output_dir="./production-output"
existing_bridge_summary=""
aws_profile="juno"
dry_run="false"

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --terraform-dir)        terraform_dir="$2"; shift 2 ;;
    --bridge-deploy-binary) bridge_deploy_binary="$2"; shift 2 ;;
    --dkg-summary)          dkg_summary="$2"; shift 2 ;;
    --base-rpc-url)         base_rpc_url="$2"; shift 2 ;;
    --base-chain-id)        base_chain_id="$2"; shift 2 ;;
    --deployer-key-file)    deployer_key_file="$2"; shift 2 ;;
    --output-dir)           output_dir="$2"; shift 2 ;;
    --existing-bridge-summary) existing_bridge_summary="$2"; shift 2 ;;
    --aws-profile)          aws_profile="$2"; shift 2 ;;
    --dry-run)              dry_run="true"; shift ;;
    *) die "unknown option: $1" ;;
  esac
done

# ── Validate ──────────────────────────────────────────────────────────────────
[[ -n "$terraform_dir" ]]       || die "--terraform-dir is required"
[[ -d "$terraform_dir" ]]       || die "terraform-dir does not exist: $terraform_dir"
[[ -n "$dkg_summary" ]]         || die "--dkg-summary is required"
[[ -f "$dkg_summary" ]]         || die "dkg-summary not found: $dkg_summary"
[[ -n "$base_rpc_url" ]]        || die "--base-rpc-url is required"
[[ -n "$base_chain_id" ]]       || die "--base-chain-id is required"

for cmd in terraform jq aws; do
  have_cmd "$cmd" || die "required command not found: $cmd"
done

mkdir -p "$output_dir"

# ── Step 1: Terraform apply for shared services ──────────────────────────────
log "Step 1: Provisioning shared infrastructure via Terraform"
if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would run: terraform -chdir=$terraform_dir init && apply"
else
  (
    cd "$terraform_dir"
    terraform init -input=false
    terraform apply -auto-approve -input=false
  )
  log "Terraform apply complete"
fi

# Extract shared infra outputs
log "Extracting Terraform outputs..."
shared_postgres_dsn=""
shared_kafka_brokers=""
shared_ipfs_api_url=""

if [[ "$dry_run" != "true" ]]; then
  shared_postgres_dsn="$(cd "$terraform_dir" && terraform output -raw postgres_dsn 2>/dev/null || true)"
  shared_kafka_brokers="$(cd "$terraform_dir" && terraform output -raw kafka_brokers 2>/dev/null || true)"
  shared_ipfs_api_url="$(cd "$terraform_dir" && terraform output -raw ipfs_api_url 2>/dev/null || true)"
fi

# ── Step 2: Deploy bridge contracts ──────────────────────────────────────────
bridge_summary=""

if [[ -n "$existing_bridge_summary" ]]; then
  log "Step 2: Reusing existing bridge contracts from $existing_bridge_summary"
  bridge_summary="$existing_bridge_summary"
else
  log "Step 2: Deploying bridge contracts"
  [[ -n "$bridge_deploy_binary" ]] || die "--bridge-deploy-binary required when not using --existing-bridge-summary"
  [[ -f "$bridge_deploy_binary" ]] || die "bridge deploy binary not found: $bridge_deploy_binary"
  [[ -n "$deployer_key_file" ]]    || die "--deployer-key-file required for bridge deployment"
  [[ -f "$deployer_key_file" ]]    || die "deployer key file not found: $deployer_key_file"

  bridge_summary="$output_dir/bridge-summary.json"

  if [[ "$dry_run" == "true" ]]; then
    log "[DRY RUN] would deploy bridge contracts"
  else
    "$bridge_deploy_binary" deploy \
      --rpc-url "$base_rpc_url" \
      --chain-id "$base_chain_id" \
      --deployer-key-file "$deployer_key_file" \
      --dkg-summary "$dkg_summary" \
      --output "$bridge_summary"

    log "Bridge contracts deployed, summary at: $bridge_summary"
  fi
fi

# ── Step 3: Generate shared-config.json ──────────────────────────────────────
log "Step 3: Generating shared-config.json"
shared_config="$output_dir/shared-config.json"

if [[ "$dry_run" == "true" ]]; then
  log "[DRY RUN] would generate $shared_config"
else
  bridge_address="$(jq -r '.contracts.bridge // empty' "$bridge_summary" 2>/dev/null || true)"
  wjuno_address="$(jq -r '.contracts.wjuno // empty' "$bridge_summary" 2>/dev/null || true)"
  operator_registry="$(jq -r '.contracts.operator_registry // empty' "$bridge_summary" 2>/dev/null || true)"
  fee_distributor="$(jq -r '.contracts.fee_distributor // empty' "$bridge_summary" 2>/dev/null || true)"
  owallet_ua="$(jq -r '.owallet_ua // empty' "$bridge_summary" 2>/dev/null || true)"
  operators_json="$(jq -c '[.operators[]?]' "$bridge_summary" 2>/dev/null || echo '[]')"

  jq -n \
    --arg base_rpc_url "$base_rpc_url" \
    --arg base_chain_id "$base_chain_id" \
    --arg postgres_dsn "$shared_postgres_dsn" \
    --arg kafka_brokers "$shared_kafka_brokers" \
    --arg ipfs_api_url "$shared_ipfs_api_url" \
    --arg bridge_address "$bridge_address" \
    --arg wjuno_address "$wjuno_address" \
    --arg operator_registry "$operator_registry" \
    --arg fee_distributor "$fee_distributor" \
    --arg owallet_ua "$owallet_ua" \
    --argjson operators "$operators_json" \
    '{
      version: "1",
      base_rpc_url: $base_rpc_url,
      base_chain_id: ($base_chain_id | tonumber),
      postgres_dsn: $postgres_dsn,
      kafka_brokers: $kafka_brokers,
      ipfs_api_url: $ipfs_api_url,
      contracts: {
        bridge: $bridge_address,
        wjuno: $wjuno_address,
        operator_registry: $operator_registry,
        fee_distributor: $fee_distributor
      },
      owallet_ua: $owallet_ua,
      operators: $operators
    }' > "$shared_config"

  log "shared-config.json written to: $shared_config"
fi

# ── Step 4: Output onboarding instructions ───────────────────────────────────
log ""
log "=== Coordinator deployment complete ==="
log ""
log "Shared config: $shared_config"
if [[ -n "$bridge_summary" && -f "$bridge_summary" ]]; then
  log "Bridge summary: $bridge_summary"
fi
log ""
log "Operator onboarding:"
log "  1. Distribute shared-config.json to each operator"
log "  2. Each operator runs: deploy-operator.sh --shared-config $shared_config --dkg-backup <backup>"
log "  3. Verify operator health with: curl <operator-host>:8080/healthz"
