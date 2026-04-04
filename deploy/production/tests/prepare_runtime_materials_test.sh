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

extract_arg() {
  local key="\$1"
  shift
  local args=( "\$@" )
  local i
  for ((i=0; i<\${#args[@]}; i++)); do
    if [[ "\${args[\$i]}" == "\$key" && \$((i + 1)) -lt \${#args[@]} ]]; then
      printf '%s\n' "\${args[\$((i + 1))]}"
      return 0
    fi
  done
  return 1
}

case "\$*" in
  *"s3api get-bucket-location"* )
    printf '{"LocationConstraint":"us-east-1"}\n'
    ;;
  *"s3api put-public-access-block"* )
    printf '{}\n'
    ;;
  *"s3api put-bucket-encryption"* )
    printf '{}\n'
    ;;
  *"s3 cp"* )
    ;;
  *"kms describe-key"* )
    key_id="\$(extract_arg --key-id "\$@" || true)"
    printf '{"KeyMetadata":{"Arn":"%s"}}\n' "\$key_id"
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

write_fake_prepare_runtime_aws_with_autoprovision() {
  local target="$1"
  local log_file="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$log_file"

extract_arg() {
  local key="\$1"
  shift
  local args=( "\$@" )
  local i
  for ((i=0; i<\${#args[@]}; i++)); do
    if [[ "\${args[\$i]}" == "\$key" && \$((i + 1)) -lt \${#args[@]} ]]; then
      printf '%s\n' "\${args[\$((i + 1))]}"
      return 0
    fi
  done
  return 1
}

case "\$*" in
  *"kms describe-key"* )
    key_id="\$(extract_arg --key-id "\$@" || true)"
    case "\$key_id" in
      alias/mainnet-op1-runtime-material|alias/mainnet-op1-runtime-config)
        exit 255
        ;;
      *)
        printf '{"KeyMetadata":{"Arn":"%s"}}\n' "\$key_id"
        ;;
    esac
    ;;
  *"kms create-key"* )
    description="\$(extract_arg --description "\$@" || true)"
    case "\$description" in
      *"alias/mainnet-op1-runtime-material"*)
        printf '{"KeyMetadata":{"Arn":"arn:aws:kms:us-east-1:021490342184:key/runtime-material-key"}}\n'
        ;;
      *"alias/mainnet-op1-runtime-config"*)
        printf '{"KeyMetadata":{"Arn":"arn:aws:kms:us-east-1:021490342184:key/runtime-config-key"}}\n'
        ;;
      *)
        printf 'unexpected create-key description: %s\n' "\$description" >&2
        exit 1
        ;;
    esac
    ;;
  *"kms create-alias"* )
    printf '{}\n'
    ;;
  *"s3api get-bucket-location"* )
    exit 255
    ;;
  *"s3api create-bucket"* )
    printf '{}\n'
    ;;
  *"s3api put-public-access-block"* )
    printf '{}\n'
    ;;
  *"s3api put-bucket-encryption"* )
    printf '{}\n'
    ;;
  *"s3 cp"* )
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

test_prepare_runtime_materials_auto_provisions_symmetric_kms_aliases_and_bucket() {
  local tmp fake_bin runtime_package runtime_config_json output_json aws_log
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  runtime_package="$tmp/runtime-material.zip"
  runtime_config_json="$tmp/runtime-config.json"
  output_json="$tmp/output.json"
  aws_log="$tmp/aws.log"
  mkdir -p "$fake_bin"

  printf 'runtime-material' >"$runtime_package"
  cat >"$runtime_config_json" <<'JSON'
{"CHECKPOINT_POSTGRES_DSN":"postgres://checkpoint.example.internal:5432/juno?sslmode=require"}
JSON

  write_fake_prepare_runtime_aws_with_autoprovision "$fake_bin/aws" "$aws_log"

  PATH="$fake_bin:$PATH" \
  bash "$REPO_ROOT/deploy/production/prepare-runtime-materials.sh" \
    --runtime-package "$runtime_package" \
    --runtime-config-json "$runtime_config_json" \
    --runtime-material-bucket "mainnet-runtime-materials" \
    --runtime-material-key "operators/op1/runtime-material.zip" \
    --runtime-material-region "us-east-1" \
    --runtime-material-kms-key-id "alias/mainnet-op1-runtime-material" \
    --runtime-config-secret-id "mainnet/op1/runtime-config" \
    --runtime-config-secret-region "us-east-1" \
    --runtime-config-secret-kms-key-id "alias/mainnet-op1-runtime-config" \
    --output "$output_json"

  assert_contains "$(cat "$aws_log")" "kms create-key --description intents-juno symmetric key for alias/mainnet-op1-runtime-material" "runtime material setup provisions the runtime material kms key when the alias is missing"
  assert_contains "$(cat "$aws_log")" "kms create-alias --alias-name alias/mainnet-op1-runtime-material --target-key-id arn:aws:kms:us-east-1:021490342184:key/runtime-material-key" "runtime material setup binds the runtime material alias to the new key"
  assert_contains "$(cat "$aws_log")" "kms create-key --description intents-juno symmetric key for alias/mainnet-op1-runtime-config" "runtime material setup provisions the runtime config kms key when the alias is missing"
  assert_contains "$(cat "$aws_log")" "s3api create-bucket --bucket mainnet-runtime-materials" "runtime material setup creates the bucket when missing"
  assert_contains "$(cat "$aws_log")" "s3api put-public-access-block --bucket mainnet-runtime-materials" "runtime material setup blocks public access on the bucket"
  assert_contains "$(cat "$aws_log")" "s3api put-bucket-encryption --bucket mainnet-runtime-materials" "runtime material setup enforces default kms encryption on the bucket"
  assert_contains "$(cat "$aws_log")" "s3 cp $runtime_package s3://mainnet-runtime-materials/operators/op1/runtime-material.zip --sse aws:kms --sse-kms-key-id arn:aws:kms:us-east-1:021490342184:key/runtime-material-key" "runtime material setup uploads with the provisioned runtime-material kms key arn"
  assert_contains "$(cat "$aws_log")" "secretsmanager create-secret --name mainnet/op1/runtime-config --secret-string" "runtime material setup creates the runtime config secret"
  assert_contains "$(cat "$aws_log")" "--kms-key-id arn:aws:kms:us-east-1:021490342184:key/runtime-config-key" "runtime material setup uses the provisioned runtime-config kms key arn for the secret"
  assert_eq "$(jq -r '.runtime_material_ref.kms_key_id' "$output_json")" "arn:aws:kms:us-east-1:021490342184:key/runtime-material-key" "runtime material setup emits the resolved runtime-material kms key arn"
  assert_eq "$(jq -r '.checkpoint_signer_kms_key_id // empty' "$output_json")" "" "runtime material setup leaves checkpoint signer kms key empty when not requested"

  rm -rf "$tmp"
}

main() {
  test_prepare_runtime_materials_uploads_refs_and_emits_manifest_fragment
  test_prepare_runtime_materials_auto_provisions_symmetric_kms_aliases_and_bucket
}

main "$@"
