#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  prepare-runtime-materials.sh [options]

Options:
  --runtime-package PATH                 required existing runtime package zip
  --runtime-config-json PATH             required runtime config JSON object
  --runtime-material-bucket NAME         required S3 bucket for runtime material
  --runtime-material-key KEY             required S3 object key for runtime material
  --runtime-material-region REGION       required AWS region for runtime material
  --runtime-material-kms-key-id ARN      required SSE-KMS key id for runtime material
  --runtime-config-secret-id ID          required Secrets Manager secret id
  --runtime-config-secret-region REGION  optional region for runtime config secret (defaults to runtime material region)
  --runtime-config-secret-kms-key-id ARN optional Secrets Manager KMS key id
  --checkpoint-signer-kms-key-id ARN     optional existing checkpoint signer KMS key id to validate
  --checkpoint-signer-alias-name NAME    optional alias name to provision a checkpoint signer key
  --checkpoint-signer-private-key-file   optional private key file used when provisioning a checkpoint signer key
  --operator-id ID                       optional operator id passed through during checkpoint signer provisioning
  --operator-address ADDRESS             required when provisioning a checkpoint signer key
  --aws-profile NAME                     optional AWS profile
  --output PATH                          optional JSON output path (default stdout)
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

runtime_package=""
runtime_config_json=""
runtime_material_bucket=""
runtime_material_key=""
runtime_material_region=""
runtime_material_kms_key_id=""
runtime_config_secret_id=""
runtime_config_secret_region=""
runtime_config_secret_kms_key_id=""
checkpoint_signer_kms_key_id=""
checkpoint_signer_alias_name=""
checkpoint_signer_private_key_file=""
operator_id=""
operator_address=""
aws_profile=""
output_path=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime-package) runtime_package="$2"; shift 2 ;;
    --runtime-config-json) runtime_config_json="$2"; shift 2 ;;
    --runtime-material-bucket) runtime_material_bucket="$2"; shift 2 ;;
    --runtime-material-key) runtime_material_key="$2"; shift 2 ;;
    --runtime-material-region) runtime_material_region="$2"; shift 2 ;;
    --runtime-material-kms-key-id) runtime_material_kms_key_id="$2"; shift 2 ;;
    --runtime-config-secret-id) runtime_config_secret_id="$2"; shift 2 ;;
    --runtime-config-secret-region) runtime_config_secret_region="$2"; shift 2 ;;
    --runtime-config-secret-kms-key-id) runtime_config_secret_kms_key_id="$2"; shift 2 ;;
    --checkpoint-signer-kms-key-id) checkpoint_signer_kms_key_id="$2"; shift 2 ;;
    --checkpoint-signer-alias-name) checkpoint_signer_alias_name="$2"; shift 2 ;;
    --checkpoint-signer-private-key-file) checkpoint_signer_private_key_file="$2"; shift 2 ;;
    --operator-id) operator_id="$2"; shift 2 ;;
    --operator-address) operator_address="$2"; shift 2 ;;
    --aws-profile) aws_profile="$2"; shift 2 ;;
    --output) output_path="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -f "$runtime_package" ]] || die "--runtime-package not found: $runtime_package"
[[ -f "$runtime_config_json" ]] || die "--runtime-config-json not found: $runtime_config_json"
[[ -n "$runtime_material_bucket" ]] || die "--runtime-material-bucket is required"
[[ -n "$runtime_material_key" ]] || die "--runtime-material-key is required"
[[ -n "$runtime_material_region" ]] || die "--runtime-material-region is required"
[[ -n "$runtime_material_kms_key_id" ]] || die "--runtime-material-kms-key-id is required"
[[ -n "$runtime_config_secret_id" ]] || die "--runtime-config-secret-id is required"
if [[ -z "$runtime_config_secret_region" ]]; then
  runtime_config_secret_region="$runtime_material_region"
fi

for cmd in aws jq; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
done

jq -e 'type == "object"' "$runtime_config_json" >/dev/null 2>&1 \
  || die "--runtime-config-json must contain a JSON object"

aws_cmd() {
  local -a aws_args=()
  if [[ -n "$aws_profile" ]]; then
    aws_args+=(--profile "$aws_profile")
  fi
  AWS_PAGER="" aws "${aws_args[@]}" "$@"
}

validate_or_provision_checkpoint_signer_key() {
  if [[ -n "$checkpoint_signer_kms_key_id" ]]; then
    aws_cmd --region "$runtime_material_region" kms describe-key --key-id "$checkpoint_signer_kms_key_id" >/dev/null
    return 0
  fi

  [[ -n "$checkpoint_signer_alias_name" ]] || return 0
  [[ -n "$checkpoint_signer_private_key_file" ]] || die "--checkpoint-signer-private-key-file is required when provisioning a checkpoint signer key"
  [[ -f "$checkpoint_signer_private_key_file" ]] || die "--checkpoint-signer-private-key-file not found: $checkpoint_signer_private_key_file"
  [[ -n "$operator_address" ]] || die "--operator-address is required when provisioning a checkpoint signer key"

  local provision_bin provision_output
  if [[ -n "${PRODUCTION_PREPARE_RUNTIME_MATERIALS_CHECKPOINT_SIGNER_BIN:-}" ]]; then
    provision_bin="${PRODUCTION_PREPARE_RUNTIME_MATERIALS_CHECKPOINT_SIGNER_BIN}"
    provision_output="$("$provision_bin" \
      --aws-profile "$aws_profile" \
      --aws-region "$runtime_material_region" \
      --alias-name "$checkpoint_signer_alias_name" \
      --operator-id "$operator_id" \
      --operator-address "$operator_address" \
      --private-key-file "$checkpoint_signer_private_key_file")"
  else
    provision_output="$(go run "$REPO_ROOT/cmd/provision-checkpoint-signer-kms" \
      --aws-profile "$aws_profile" \
      --aws-region "$runtime_material_region" \
      --alias-name "$checkpoint_signer_alias_name" \
      --operator-id "$operator_id" \
      --operator-address "$operator_address" \
      --private-key-file "$checkpoint_signer_private_key_file")"
  fi
  checkpoint_signer_kms_key_id="$(jq -r '.keyArn // .keyId // empty' <<<"$provision_output")"
  [[ -n "$checkpoint_signer_kms_key_id" ]] || die "checkpoint signer provisioner returned no key id"
}

upsert_runtime_config_secret() {
  local secret_payload
  secret_payload="$(cat "$runtime_config_json")"

  if aws_cmd --region "$runtime_config_secret_region" secretsmanager describe-secret --secret-id "$runtime_config_secret_id" >/dev/null 2>&1; then
    aws_cmd --region "$runtime_config_secret_region" secretsmanager put-secret-value \
      --secret-id "$runtime_config_secret_id" \
      --secret-string "$secret_payload" >/dev/null
    return 0
  fi

  local -a create_args=(
    --region "$runtime_config_secret_region"
    secretsmanager create-secret
    --name "$runtime_config_secret_id"
    --secret-string "$secret_payload"
  )
  if [[ -n "$runtime_config_secret_kms_key_id" ]]; then
    create_args+=(--kms-key-id "$runtime_config_secret_kms_key_id")
  fi
  aws_cmd "${create_args[@]}" >/dev/null
}

upload_runtime_package() {
  aws_cmd --region "$runtime_material_region" s3 cp \
    "$runtime_package" "s3://${runtime_material_bucket}/${runtime_material_key}" \
    --sse aws:kms \
    --sse-kms-key-id "$runtime_material_kms_key_id" >/dev/null
}

validate_or_provision_checkpoint_signer_key
upload_runtime_package
upsert_runtime_config_secret

result_json="$(jq -n \
  --arg runtime_material_bucket "$runtime_material_bucket" \
  --arg runtime_material_key "$runtime_material_key" \
  --arg runtime_material_region "$runtime_material_region" \
  --arg runtime_material_kms_key_id "$runtime_material_kms_key_id" \
  --arg runtime_config_secret_id "$runtime_config_secret_id" \
  --arg runtime_config_secret_region "$runtime_config_secret_region" \
  --arg checkpoint_signer_kms_key_id "$checkpoint_signer_kms_key_id" \
  '{
    runtime_material_ref: {
      mode: "s3-kms-zip",
      bucket: $runtime_material_bucket,
      key: $runtime_material_key,
      region: $runtime_material_region,
      kms_key_id: $runtime_material_kms_key_id
    },
    runtime_config_secret_id: $runtime_config_secret_id,
    runtime_config_secret_region: $runtime_config_secret_region,
    checkpoint_signer_kms_key_id: (if $checkpoint_signer_kms_key_id == "" then null else $checkpoint_signer_kms_key_id end)
  }')"

if [[ -n "$output_path" ]]; then
  printf '%s\n' "$result_json" >"$output_path"
else
  printf '%s\n' "$result_json"
fi
