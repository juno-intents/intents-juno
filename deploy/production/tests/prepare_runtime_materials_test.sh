#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

write_fake_prepare_runtime_aws() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$log_file"

case "\$*" in
  *"s3 cp"* )
    ;;
  *"kms describe-key"* )
    printf '{"KeyMetadata":{"Arn":"arn:aws:kms:us-east-1:021490342184:key/existing"}}\n'
    ;;
  *"secretsmanager describe-secret"* )
    exit 255
    ;;
  *"secretsmanager create-secret"* )
    printf '{"ARN":"arn:aws:secretsmanager:us-east-1:021490342184:secret:mainnet-op1-runtime-config"}\n'
    ;;
  *"secretsmanager put-secret-value"* )
    printf '{"VersionId":"version-1"}\n'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "\$*" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$target"
}

write_fake_checkpoint_signer_provisioner() {
  local target="$1"
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' '{"keyArn":"arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555"}'
EOF
  chmod 0755 "$target"
}

test_prepare_runtime_materials_uploads_refs_and_emits_manifest_fragment() {
  local tmp fake_bin runtime_package runtime_config_json output_json aws_log provisioner private_key
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  runtime_package="$tmp/runtime-material.zip"
  runtime_config_json="$tmp/runtime-config.json"
  output_json="$tmp/output.json"
  aws_log="$tmp/aws.log"
  provisioner="$tmp/fake-provision-checkpoint-signer-kms"
  private_key="$tmp/checkpoint-signer.key"
  mkdir -p "$fake_bin"

  printf 'runtime-material' >"$runtime_package"
  cat >"$runtime_config_json" <<'JSON'
{"CHECKPOINT_POSTGRES_DSN":"aws-sm://runtime/checkpoint-postgres","JUNO_RPC_USER":"aws-sm://runtime/juno-rpc-user"}
JSON
  printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' >"$private_key"

  write_fake_prepare_runtime_aws "$fake_bin/aws" "$aws_log"
  write_fake_checkpoint_signer_provisioner "$provisioner"

  PATH="$fake_bin:$PATH" \
  PRODUCTION_PREPARE_RUNTIME_MATERIALS_CHECKPOINT_SIGNER_BIN="$provisioner" \
  bash "$REPO_ROOT/deploy/production/prepare-runtime-materials.sh" \
    --runtime-package "$runtime_package" \
    --runtime-config-json "$runtime_config_json" \
    --runtime-material-bucket "mainnet-runtime-materials" \
    --runtime-material-key "operators/op1/runtime-material.zip" \
    --runtime-material-region "us-east-1" \
    --runtime-material-kms-key-id "arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd" \
    --runtime-config-secret-id "mainnet/op1/runtime-config" \
    --runtime-config-secret-region "us-east-1" \
    --checkpoint-signer-alias-name "alias/mainnet-op1-checkpoint-signer" \
    --checkpoint-signer-private-key-file "$private_key" \
    --operator-id "0x1111111111111111111111111111111111111111" \
    --operator-address "0x9999999999999999999999999999999999999999" \
    --aws-profile "juno" \
    --output "$output_json"

  assert_contains "$(cat "$aws_log")" "s3 cp $runtime_package s3://mainnet-runtime-materials/operators/op1/runtime-material.zip --sse aws:kms --sse-kms-key-id arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd" "runtime material setup uploads the runtime package to s3 with kms encryption"
  assert_contains "$(cat "$aws_log")" "secretsmanager create-secret --name mainnet/op1/runtime-config" "runtime material setup creates the runtime config secret"
  assert_eq "$(jq -r '.runtime_material_ref.mode' "$output_json")" "s3-kms-zip" "runtime material setup emits the runtime material mode"
  assert_eq "$(jq -r '.runtime_config_secret_id' "$output_json")" "mainnet/op1/runtime-config" "runtime material setup emits the runtime config secret id"
  assert_eq "$(jq -r '.checkpoint_signer_kms_key_id' "$output_json")" "arn:aws:kms:us-east-1:021490342184:key/11111111-2222-3333-4444-555555555555" "runtime material setup emits the checkpoint signer kms key id"

  rm -rf "$tmp"
}

main() {
  test_prepare_runtime_materials_uploads_refs_and_emits_manifest_fragment
}

main "$@"
