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

write_shared_manifest_for_ssm_canary() {
  local target="$1"
  local proof_asg="${2:-alpha-proof-role}"
  jq -n \
    --arg proof_asg "$proof_asg" \
    '{
      environment: "alpha",
      shared_services: {
        aws_profile: "juno",
        aws_region: "us-east-1",
        proof_queue: {
          shadow: {
            driver: "postgres"
          }
        },
        postgres: {
          endpoint: "postgres.alpha.internal",
          port: 5432
        },
        kafka: {
          bootstrap_brokers: "broker-1.alpha.internal:9098",
          auth: {
            mode: "aws-msk-iam",
            aws_region: "us-east-1"
          }
        },
        ipfs: {
          api_url: "https://ipfs.alpha.internal"
        }
      },
      shared_roles: {
        proof: {
          asg: $proof_asg
        }
      }
    }' >"$target"
}

write_fake_aws_for_shared_ssm() {
  local target="$1"
  local log_dir="$2"
  local asg_instance_id="${3:-i-proof001}"
  local instance_name="${4:-alpha-proof-role}"
  local instance_state="${5:-running}"
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

decode_ssm_command() {
  local wrapped="\$1"
  awk '
    /__INTENTS_JUNO_SSM_COMMAND__/ && !seen {
      seen = 1
      next
    }
    /^__INTENTS_JUNO_SSM_COMMAND__\$/ && seen {
      exit
    }
    seen {
      print
    }
  ' <<<"\$wrapped" | base64 --decode
}

case "\$*" in
  *"autoscaling describe-auto-scaling-groups"*"alpha-proof-role"*)
    printf '{"AutoScalingGroups":[{"Instances":[{"InstanceId":"$asg_instance_id","LifecycleState":"InService","HealthStatus":"Healthy"}]}]}\n'
    ;;
  *"ec2 describe-instances"*"--instance-ids $asg_instance_id"*)
    printf '{"Reservations":[{"Instances":[{"InstanceId":"$asg_instance_id","State":{"Name":"$instance_state"},"Tags":[{"Key":"Name","Value":"$instance_name"}]}]}]}\n'
    ;;
  *"ssm send-command"*)
    params="\$(resolve_parameters "\$@" || true)"
    command_text="\$(jq -r '.commands[0] // empty' <<<"\$params" 2>/dev/null || true)"
    if [[ -n "\$command_text" ]]; then
      if decoded="\$(decode_ssm_command "\$command_text" 2>/dev/null)" && [[ -n "\$decoded" ]]; then
        printf '%s\n' "\$decoded" >>"$log_dir/commands.log"
      else
        printf '%s\n' "\$command_text" >>"$log_dir/commands.log"
      fi
    else
      printf '%s\n' "\$params" >>"$log_dir/commands.log"
    fi
    counter_file="$log_dir/command-counter"
    counter=0
    if [[ -f "\$counter_file" ]]; then
      counter="\$(cat "\$counter_file")"
    fi
    counter=\$((counter + 1))
    printf '%s' "\$counter" >"\$counter_file"
    printf '{"Command":{"CommandId":"cmd-%s"}}\n' "\$counter"
    ;;
  *"ssm get-command-invocation"*)
    printf '%s\n' '{"Status":"Success","StandardOutputContent":"{\"ready_for_deploy\":true,\"checks\":{\"queue\":{\"status\":\"passed\",\"detail\":\"queue-inspect passed for 5 targets\"}}}","StandardErrorContent":""}'
    ;;
  *)
    printf 'unexpected aws invocation: %s\n' "\$*" >&2
    exit 1
    ;;
esac
EOF
  chmod 0755 "$target"
}

test_shared_services_ssm_canary_dry_run_validates_manifest_without_aws() {
  local tmp manifest output_json fake_bin log_file
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  output_json="$tmp/output.json"
  fake_bin="$tmp/bin"
  log_file="$tmp/local-probes.log"
  mkdir -p "$fake_bin"
  write_shared_manifest_for_ssm_canary "$manifest"

  for cmd in aws pg_isready nc curl; do
    cat >"$fake_bin/$cmd" <<EOF
#!/usr/bin/env bash
printf '$cmd %s\n' "\$*" >>"$log_file"
exit 1
EOF
    chmod 0755 "$fake_bin/$cmd"
  done

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --dry-run >"$output_json"
  )

  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "false" "dry-run output is not deploy-ready"
  assert_eq "$(jq -r '.checks.ssm.status' "$output_json")" "skipped" "dry-run skips ssm"
  if [[ -f "$log_file" ]]; then
    printf 'dry run should not call aws or private endpoint probes\n' >&2
    exit 1
  fi

  rm -rf "$tmp"
}

test_shared_services_ssm_canary_runs_remote_shared_canary() {
  local tmp manifest fake_bin log_dir output_json queue_inspect_bin local_probe_log
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  fake_bin="$tmp/bin"
  log_dir="$tmp/logs"
  output_json="$tmp/output.json"
  queue_inspect_bin="$tmp/queue-inspect"
  local_probe_log="$log_dir/local-probes.log"
  mkdir -p "$fake_bin" "$log_dir"
  write_shared_manifest_for_ssm_canary "$manifest"
  write_fake_aws_for_shared_ssm "$fake_bin/aws" "$log_dir"

  cat >"$queue_inspect_bin" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod 0755 "$queue_inspect_bin"
  for cmd in pg_isready nc curl; do
    cat >"$fake_bin/$cmd" <<EOF
#!/usr/bin/env bash
printf '$cmd %s\n' "\$*" >>"$local_probe_log"
exit 99
EOF
    chmod 0755 "$fake_bin/$cmd"
  done

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-bin "$queue_inspect_bin" >"$output_json"
  )

  assert_contains "$(cat "$log_dir/aws.log")" "autoscaling describe-auto-scaling-groups --auto-scaling-group-names alpha-proof-role" "ssm canary resolves proof role asg"
  assert_contains "$(cat "$log_dir/aws.log")" "ec2 describe-instances --instance-ids i-proof001" "ssm canary validates candidate instance metadata"
  assert_contains "$(cat "$log_dir/aws.log")" "ssm send-command --instance-ids i-proof001" "ssm canary runs against proof role instance"
  assert_contains "$(cat "$log_dir/commands.log")" "deploy/production/canary-shared-services.sh" "ssm canary stages the shared canary script"
  assert_contains "$(cat "$log_dir/commands.log")" "deploy/production/lib.sh" "ssm canary stages production lib dependency"
  assert_contains "$(cat "$log_dir/commands.log")" "deploy/operators/dkg/common.sh" "ssm canary stages dkg common dependency"
  assert_contains "$(cat "$log_dir/commands.log")" 'export HOME="${HOME:-/root}"' "remote canary normalizes HOME for non-login ssm shells"
  assert_contains "$(cat "$log_dir/commands.log")" "PRODUCTION_CANARY_AWS_USE_INSTANCE_PROFILE=true" "remote canary uses instance profile credentials"
  assert_contains "$(cat "$log_dir/commands.log")" "PRODUCTION_CANARY_QUEUE_INSPECT_BIN=" "remote canary receives staged queue-inspect binary"
  assert_contains "$(cat "$log_dir/commands.log")" "PRODUCTION_CANARY_QUEUE_INSPECT_POSTGRES_DSN_ENV=POSTGRES_DSN" "remote canary reads proof role postgres dsn env"
  assert_contains "$(cat "$log_dir/commands.log")" "source /etc/intents-juno/proof-requestor.env" "remote canary sources proof requestor env"
  assert_contains "$(cat "$log_dir/commands.log")" "trap cleanup EXIT" "remote canary cleans up stage dir on exit"
  assert_not_contains "$(cat "$log_dir/commands.log")" "postgres://queue.example.invalid" "remote canary does not expose dsn in command text"
  if [[ -f "$local_probe_log" ]]; then
    printf 'ssm wrapper should not run private endpoint probes locally\n' >&2
    exit 1
  fi
  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "ssm canary returns remote ready flag"
  assert_eq "$(jq -r '.checks.queue.status' "$output_json")" "passed" "ssm canary returns remote queue status"

  rm -rf "$tmp"
}

test_shared_services_ssm_canary_downloads_queue_inspect_release_on_remote_host() {
  local tmp manifest fake_bin log_dir output_json local_probe_log commands
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  fake_bin="$tmp/bin"
  log_dir="$tmp/logs"
  output_json="$tmp/output.json"
  local_probe_log="$log_dir/local-probes.log"
  mkdir -p "$fake_bin" "$log_dir"
  write_shared_manifest_for_ssm_canary "$manifest"
  write_fake_aws_for_shared_ssm "$fake_bin/aws" "$log_dir"

  for cmd in pg_isready nc curl; do
    cat >"$fake_bin/$cmd" <<EOF
#!/usr/bin/env bash
printf '$cmd %s\n' "\$*" >>"$local_probe_log"
exit 99
EOF
    chmod 0755 "$fake_bin/$cmd"
  done

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-release-tag app-binaries-v2026.07.03-r1-mainnet \
      --github-repo juno-intents/intents-juno >"$output_json"
  )

  commands="$(cat "$log_dir/commands.log")"
  assert_contains "$commands" "curl -fsSL https://github.com/juno-intents/intents-juno/releases/download/app-binaries-v2026.07.03-r1-mainnet/queue-inspect_linux_amd64 -o" "release mode downloads queue-inspect binary on the remote host"
  assert_contains "$commands" "curl -fsSL https://github.com/juno-intents/intents-juno/releases/download/app-binaries-v2026.07.03-r1-mainnet/queue-inspect_linux_amd64.sha256 -o" "release mode downloads queue-inspect checksum on the remote host"
  assert_contains "$commands" 'command -v "$cmd" >/dev/null' "release mode preflights remote download tools"
  assert_contains "$commands" "queue_inspect_expected=\"\$(awk 'NF {print \$1; exit}'" "release mode parses the checksum field"
  assert_contains "$commands" "sha256sum -c - >/dev/null" "release mode suppresses checksum stdout before canary JSON"
  assert_contains "$commands" "install -m 0755" "release mode installs the verified queue-inspect binary"
  assert_contains "$commands" "PRODUCTION_CANARY_QUEUE_INSPECT_BIN=" "release mode passes queue-inspect path to the remote canary"
  assert_not_contains "$commands" "queue-inspect.b64" "release mode does not stage a local queue-inspect binary over ssm"
  assert_not_contains "$commands" "sha256sum -c queue-inspect_linux_amd64.sha256" "release mode does not run checksum validation with stdout pollution"
  if [[ -f "$local_probe_log" ]]; then
    printf 'ssm release wrapper should not run private endpoint probes locally\n' >&2
    exit 1
  fi
  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "ssm release canary returns remote ready flag"
  assert_eq "$(jq -r '.checks.queue.status' "$output_json")" "passed" "ssm release canary returns remote queue status"

  rm -rf "$tmp"
}

test_shared_services_ssm_canary_fetches_queue_dsn_secret_on_remote_host() {
  local tmp manifest fake_bin log_dir output_json commands secret_arn
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  fake_bin="$tmp/bin"
  log_dir="$tmp/logs"
  output_json="$tmp/output.json"
  secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:intents-juno-shared-mainnet-shared-postgres-dsn-AbCdEf"
  mkdir -p "$fake_bin" "$log_dir"
  write_shared_manifest_for_ssm_canary "$manifest"
  write_fake_aws_for_shared_ssm "$fake_bin/aws" "$log_dir"

  (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-release-tag app-binaries-v2026.07.03-r1-mainnet \
      --queue-inspect-postgres-dsn-secret-arn "$secret_arn" >"$output_json"
  )

  commands="$(cat "$log_dir/commands.log")"
  assert_contains "$commands" "command -v aws >/dev/null" "secret mode preflights remote aws cli"
  assert_contains "$commands" "aws --region us-east-1 secretsmanager get-secret-value --secret-id $secret_arn --query SecretString --output text" "secret mode fetches queue dsn with instance profile"
  assert_contains "$commands" 'POSTGRES_DSN="$(AWS_PAGER="" aws' "secret mode captures the dsn without printing it"
  assert_contains "$commands" '[[ -z "$POSTGRES_DSN" || "$POSTGRES_DSN" == "None" ]]' "secret mode validates non-empty secret value"
  assert_contains "$commands" "export POSTGRES_DSN" "secret mode exports dsn for queue-inspect"
  assert_contains "$commands" "PRODUCTION_CANARY_QUEUE_INSPECT_POSTGRES_DSN_ENV=POSTGRES_DSN" "secret mode keeps queue-inspect env indirection"
  assert_not_contains "$commands" "source /etc/intents-juno/proof-requestor.env" "secret mode does not require a host runtime env file"
  assert_not_contains "$commands" "postgres://queue.example.invalid" "secret mode does not expose dsn in command text"
  assert_eq "$(jq -r '.ready_for_deploy' "$output_json")" "true" "ssm secret canary returns remote ready flag"
  assert_eq "$(jq -r '.checks.queue.status' "$output_json")" "passed" "ssm secret canary returns remote queue status"

  rm -rf "$tmp"
}

test_shared_services_ssm_canary_rejects_invalid_release_inputs() {
  local tmp manifest queue_inspect_bin output_json stderr
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  queue_inspect_bin="$tmp/queue-inspect"
  output_json="$tmp/output.json"
  stderr="$tmp/stderr"
  write_shared_manifest_for_ssm_canary "$manifest"
  cat >"$queue_inspect_bin" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
  chmod 0755 "$queue_inspect_bin"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-release-tag latest \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject latest release tag\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "pinned app-binaries release" "release tag must be pinned"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-release-tag app-binaries-v2026.07.03-r1-mainnet \
      --github-repo "bad repo" \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject invalid github repo\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "owner/name syntax" "github repo is validated before remote command rendering"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --github-repo juno-intents/intents-juno \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject github repo without release tag\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "--github-repo requires --queue-inspect-release-tag" "github repo override requires release mode"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-release-tag "" \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject empty release tag\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "--queue-inspect-release-tag must not be empty" "explicit empty release tag is rejected"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --github-repo "" \
      --queue-inspect-release-tag app-binaries-v2026.07.03-r1-mainnet \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject empty github repo\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "--github-repo must not be empty" "explicit empty github repo is rejected"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-bin "$queue_inspect_bin" \
      --queue-inspect-release-tag app-binaries-v2026.07.03-r1-mainnet \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject both queue-inspect modes\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "mutually exclusive" "local and release queue-inspect modes are mutually exclusive"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-bin "" \
      --queue-inspect-release-tag app-binaries-v2026.07.03-r1-mainnet \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject both queue-inspect modes even with empty local bin\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "mutually exclusive" "mutual exclusion uses provided flags instead of non-empty values"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-bin "" \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject empty local queue-inspect bin\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "--queue-inspect-bin must not be empty" "explicit empty local queue-inspect path is rejected"

  rm -rf "$tmp"
}

test_shared_services_ssm_canary_rejects_invalid_queue_dsn_secret_inputs() {
  local tmp manifest output_json stderr secret_arn
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  output_json="$tmp/output.json"
  stderr="$tmp/stderr"
  secret_arn="arn:aws:secretsmanager:us-east-1:123456789012:secret:intents-juno-shared-mainnet-shared-postgres-dsn-AbCdEf"
  write_shared_manifest_for_ssm_canary "$manifest"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-postgres-dsn-secret-arn "$secret_arn" \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject queue dsn secret without queue inspection\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "requires queue inspection" "queue dsn secret requires queue inspection mode"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-release-tag app-binaries-v2026.07.03-r1-mainnet \
      --queue-inspect-postgres-dsn-secret-arn "" \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject empty queue dsn secret arn\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "--queue-inspect-postgres-dsn-secret-arn must not be empty" "explicit empty queue dsn secret arn is rejected"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-release-tag app-binaries-v2026.07.03-r1-mainnet \
      --queue-inspect-postgres-dsn-secret-arn "not-an-arn" \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject invalid queue dsn secret arn\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "Secrets Manager secret ARN" "queue dsn secret arn syntax is validated locally"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" \
      --queue-inspect-release-tag app-binaries-v2026.07.03-r1-mainnet \
      --queue-inspect-postgres-dsn-secret-arn "$secret_arn" \
      --remote-runtime-env /etc/intents-juno/proof-requestor.env \
      --dry-run >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject both queue dsn secret and remote runtime env\n' >&2
    exit 1
  fi
  assert_contains "$(cat "$stderr")" "mutually exclusive" "queue dsn secret and runtime env are mutually exclusive"

  rm -rf "$tmp"
}

test_shared_services_ssm_canary_requires_proof_asg() {
  local tmp manifest output_json stderr
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  output_json="$tmp/output.json"
  stderr="$tmp/stderr"
  write_shared_manifest_for_ssm_canary "$manifest" ""
  jq 'del(.shared_roles.proof.asg)' "$manifest" >"$manifest.tmp"
  mv "$manifest.tmp" "$manifest"

  if (
    cd "$REPO_ROOT"
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject missing proof asg\n' >&2
    exit 1
  fi

  assert_contains "$(cat "$stderr")" "shared manifest is missing shared_roles.proof.asg" "missing proof asg is rejected"

  rm -rf "$tmp"
}

test_shared_services_ssm_canary_rejects_protected_instance_id_before_ssm() {
  local tmp manifest fake_bin log_dir output_json stderr
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  fake_bin="$tmp/bin"
  log_dir="$tmp/logs"
  output_json="$tmp/output.json"
  stderr="$tmp/stderr"
  mkdir -p "$fake_bin" "$log_dir"
  write_shared_manifest_for_ssm_canary "$manifest"
  write_fake_aws_for_shared_ssm "$fake_bin/aws" "$log_dir" "i-0a886419721b81020" "alpha-proof-role"

  if (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject protected instance id\n' >&2
    exit 1
  fi

  assert_contains "$(cat "$stderr")" "protected instance id selected by shared proof asg" "protected instance id is rejected"
  assert_not_contains "$(cat "$log_dir/aws.log")" "ec2 describe-instances" "protected ids are rejected before ec2 metadata lookup"
  assert_not_contains "$(cat "$log_dir/aws.log")" "ssm send-command" "protected ids are rejected before ssm"

  rm -rf "$tmp"
}

test_shared_services_ssm_canary_rejects_protected_instance_name_before_ssm() {
  local tmp manifest fake_bin log_dir output_json stderr
  tmp="$(mktemp -d)"
  manifest="$tmp/shared-manifest.json"
  fake_bin="$tmp/bin"
  log_dir="$tmp/logs"
  output_json="$tmp/output.json"
  stderr="$tmp/stderr"
  mkdir -p "$fake_bin" "$log_dir"
  write_shared_manifest_for_ssm_canary "$manifest"
  write_fake_aws_for_shared_ssm "$fake_bin/aws" "$log_dir" "i-proof001" "nn"

  if (
    cd "$REPO_ROOT"
    PATH="$fake_bin:$PATH" \
    bash deploy/production/canary-shared-services-ssm.sh \
      --shared-manifest "$manifest" >"$output_json" 2>"$stderr"
  ); then
    printf 'expected ssm canary to reject protected instance name\n' >&2
    exit 1
  fi

  assert_contains "$(cat "$stderr")" "protected instance name selected by shared proof asg" "protected instance name is rejected"
  assert_contains "$(cat "$log_dir/aws.log")" "ec2 describe-instances --instance-ids i-proof001" "name denylist uses candidate metadata"
  assert_not_contains "$(cat "$log_dir/aws.log")" "ssm send-command" "protected names are rejected before ssm"

  rm -rf "$tmp"
}

main() {
  test_shared_services_ssm_canary_dry_run_validates_manifest_without_aws
  test_shared_services_ssm_canary_runs_remote_shared_canary
  test_shared_services_ssm_canary_downloads_queue_inspect_release_on_remote_host
  test_shared_services_ssm_canary_fetches_queue_dsn_secret_on_remote_host
  test_shared_services_ssm_canary_rejects_invalid_release_inputs
  test_shared_services_ssm_canary_rejects_invalid_queue_dsn_secret_inputs
  test_shared_services_ssm_canary_requires_proof_asg
  test_shared_services_ssm_canary_rejects_protected_instance_id_before_ssm
  test_shared_services_ssm_canary_rejects_protected_instance_name_before_ssm
}

main "$@"
