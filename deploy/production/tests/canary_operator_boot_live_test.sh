#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
source "$SCRIPT_DIR/common_test.sh"

assert_not_contains() {
  local haystack="$1"
  local needle="$2"
  local msg="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    printf 'assert_not_contains failed: %s: found=%q\n' "$msg" "$needle" >&2
    exit 1
  fi
}

write_fake_live_aws() {
  local target="$1"
  local log_dir="$2"
  cat >"$target" <<EOF
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "\$*" >>"$log_dir/aws.log"

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

resolve_parameters() {
  local raw
  raw="\$(extract_arg --parameters "\$@" || true)"
  if [[ "\$raw" == file://* ]]; then
    cat "\${raw#file://}"
    return 0
  fi
  printf '%s' "\$raw"
}

case "\$*" in
  *"ec2 describe-instances"*"--query Reservations[].Instances[].InstanceId"* )
    printf 'i-op001\n'
    ;;
  *"ssm send-command"* )
    params="\$(resolve_parameters "\$@" || true)"
    printf '%s\n' "\$params" >>"$log_dir/commands.log"
    counter_file="$log_dir/command-counter"
    counter=0
    if [[ -f "\$counter_file" ]]; then
      counter="\$(cat "\$counter_file")"
    fi
    counter=\$((counter + 1))
    printf '%s' "\$counter" >"\$counter_file"
    printf '{"Command":{"CommandId":"cmd-%s"}}\n' "\$counter"
    ;;
  *"ssm get-command-invocation"* )
    printf '%s\n' '{"Status":"Success","StandardOutputContent":"{\"operator_id\":\"0x1111111111111111111111111111111111111111\",\"ready_for_deploy\":true,\"checks\":{\"inputs\":{\"status\":\"passed\",\"detail\":\"runtime material refs present\"},\"relayer_funding\":{\"status\":\"skipped\",\"detail\":\"host-local flow does not resolve relayer keys on the runner\"},\"withdraw_config\":{\"status\":\"passed\",\"detail\":\"operator env is staged correctly\"},\"txsign_runtime\":{\"status\":\"passed\",\"detail\":\"juno-txsign supports sign-digest\"},\"systemd\":{\"status\":\"passed\",\"detail\":\"all operator services active\"},\"junocashd_sync\":{\"status\":\"passed\",\"detail\":\"junocashd is caught up enough\"},\"deposit_relayer_ready\":{\"status\":\"passed\",\"detail\":\"deposit-relayer /readyz passed\"},\"kms_export\":{\"status\":\"passed\",\"detail\":\"runtime export receipt is present\"},\"scan_catchup\":{\"status\":\"passed\",\"detail\":\"juno-scan is within 1 block(s) of local tip 5000\"}}}","StandardErrorContent":""}'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "\$*" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$target"
}

test_operator_boot_canary_uses_host_local_ssm_path_for_live_rollout() {
  local tmp fake_bin log_dir manifest output_json shared_manifest operator_id ssh_log
  tmp="$(mktemp -d)"
  fake_bin="$tmp/bin"
  log_dir="$tmp/logs"
  manifest="$tmp/operator-deploy.json"
  output_json="$tmp/output.json"
  shared_manifest="$tmp/shared-manifest.json"
  operator_id="0x1111111111111111111111111111111111111111"
  ssh_log="$log_dir/ssh.log"
  mkdir -p "$fake_bin" "$log_dir"

  cat >"$shared_manifest" <<'JSON'
{"shared_services":{}}
JSON
  cat >"$manifest" <<JSON
{
  "version": "3",
  "environment": "mainnet",
  "operator_id": "$operator_id",
  "operator_host": "203.0.113.11",
  "operator_user": "ubuntu",
  "runtime_dir": "/var/lib/intents-juno/operator-runtime",
  "shared_manifest_path": "$shared_manifest",
  "aws_profile": "juno",
  "aws_region": "us-east-1",
  "runtime_material_ref": {
    "mode": "s3-kms-zip",
    "bucket": "mainnet-runtime-materials",
    "key": "operators/op1/runtime-material.zip",
    "region": "us-east-1",
    "kms_key_id": "arn:aws:kms:us-east-1:021490342184:key/99999999-aaaa-bbbb-cccc-dddddddddddd"
  },
  "runtime_config_secret_id": "mainnet/op1/runtime-config",
  "runtime_config_secret_region": "us-east-1"
}
JSON

  write_fake_live_aws "$fake_bin/aws" "$log_dir"
  cat >"$fake_bin/ssh" <<EOF
#!/usr/bin/env bash
printf 'ssh %s\n' "\$*" >>"$ssh_log"
exit 1
EOF
  chmod 0755 "$fake_bin/ssh"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-operator-boot.sh \
      --operator-deploy "$manifest" >"$output_json"
  )

  assert_contains "$(cat "$log_dir/aws.log")" "ssm send-command --instance-ids i-op001" "live canary uses ssm commands"
  assert_contains "$(cat "$log_dir/commands.log")" "run-operator-local-canary.sh" "live canary stages the host-local canary helper"
  assert_not_contains "$(cat "$log_dir/commands.log")" "operator-secrets.env" "live canary does not resolve local secret contracts"
  assert_not_contains "$(cat "$log_dir/commands.log")" "known_hosts" "live canary does not require ssh trust roots"
  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "live canary returns a ready flag"
  assert_eq "$(jq -r '.checks.relayer_funding.status' "$output_json")" "skipped" "live canary skips local relayer funding resolution"
  assert_eq "$(jq -r '.checks.systemd.status' "$output_json")" "passed" "live canary validates systemd via the host-local probe"
  if [[ -f "$ssh_log" ]]; then
    printf 'expected no ssh usage in the live canary path\n' >&2
    exit 1
  fi

  rm -rf "$tmp"
}

main() {
  test_operator_boot_canary_uses_host_local_ssm_path_for_live_rollout
}

main "$@"
