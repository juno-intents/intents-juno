#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"
prepare_script_runtime "$SCRIPT_DIR"

cleanup_enabled="false"
cleanup_workdir=""
cleanup_terraform_dir=""
cleanup_aws_profile=""
cleanup_aws_region=""

usage() {
  cat <<'EOF'
Usage:
  run-testnet-e2e-aws.sh run [options] -- [run-testnet-e2e.sh args...]
  run-testnet-e2e-aws.sh cleanup [options]

Commands:
  run:
    Provisions an AWS runner via Terraform, executes the live testnet e2e flow
    on the runner, collects artifacts locally, and tears down infra by default.

  cleanup:
    Idempotent fallback destroy for previously created infra state in workdir.

run options:
  --workdir <path>                     local workdir (default: <repo>/tmp/aws-live-e2e)
  --terraform-dir <path>               terraform dir (default: <repo>/deploy/shared/terraform/live-e2e)
  --aws-region <region>                AWS region (required)
  --aws-profile <name>                 optional AWS profile for local execution
  --aws-name-prefix <prefix>           terraform name prefix (default: juno-live-e2e)
  --aws-instance-type <type>           runner instance type (default: c7i.4xlarge)
  --runner-ami-id <ami-id>             optional custom AMI for runner host
  --aws-root-volume-gb <n>             root volume size (default: 200)
  --operator-instance-count <n>        operator host count (default: 5)
  --operator-instance-type <type>      operator instance type (default: c7i.large)
  --operator-ami-id <ami-id>           optional custom AMI for operator hosts
  --operator-root-volume-gb <n>        operator root volume size (default: 100)
  --shared-ami-id <ami-id>             optional custom AMI for shared IPFS pinning ASG instances
  --operator-base-port <port>          first operator grpc port (default: 18443)
  --dkg-s3-key-prefix <prefix>         S3 prefix for KMS-exported key packages (default: dkg/keypackages)
  --dkg-release-tag <tag>              DKG release tag for distributed ceremony (default: v0.1.0)
  --ssh-allowed-cidr <cidr>            inbound SSH CIDR (default: caller public IP /32)
  --base-funder-key-file <path>        file with Base funder private key hex (required)
  --juno-funder-key-file <path>        file with Juno funder private key hex (required)
  --juno-rpc-user-file <path>          file with junocashd RPC username for witness extraction (required)
  --juno-rpc-pass-file <path>          file with junocashd RPC password for witness extraction (required)
  --juno-scan-bearer-token-file <path> optional file with juno-scan bearer token for witness extraction
  --boundless-requestor-key-file <p>   optional file with Boundless requestor private key hex
  --without-shared-services            skip provisioning managed shared services (Aurora/MSK/ECS/IPFS)
  --shared-postgres-user <user>        shared Aurora Postgres username (default: postgres)
  --shared-postgres-db <name>          shared Aurora Postgres DB name (default: intents_e2e)
  --shared-postgres-port <port>        shared Aurora Postgres TCP port (default: 5432)
  --shared-kafka-port <port>           shared MSK plaintext Kafka TCP port (default: 9092)
  --keep-infra                         do not destroy infra at the end

cleanup options:
  --workdir <path>                     local workdir (default: <repo>/tmp/aws-live-e2e)
  --terraform-dir <path>               terraform dir (default: <repo>/deploy/shared/terraform/live-e2e)
  --aws-region <region>                optional AWS region override
  --aws-profile <name>                 optional AWS profile override

Notes:
  - Arguments after '--' are forwarded to:
      deploy/operators/dkg/e2e/run-testnet-e2e.sh run ...
  - The wrapper always injects:
      --workdir /home/ubuntu/testnet-e2e-live
      --base-funder-key-file .ci/secrets/base-funder.key
      --output /home/ubuntu/testnet-e2e-live/reports/testnet-e2e-summary.json
      --force
EOF
}

ensure_local_command() {
  local cmd="$1"
  if ! have_cmd "$cmd"; then
    die "missing required command: $cmd"
  fi
}

trimmed_file_value() {
  local path="$1"
  tr -d '\r\n' <"$path"
}

shell_join() {
  local out=""
  local arg
  for arg in "$@"; do
    out+=" $(printf '%q' "$arg")"
  done
  printf '%s' "${out# }"
}

forwarded_arg_value() {
  local flag="$1"
  shift
  local -a args=("$@")

  local idx=0
  while (( idx < ${#args[@]} )); do
    if [[ "${args[$idx]}" == "$flag" ]]; then
      if (( idx + 1 >= ${#args[@]} )); then
        die "forwarded argument missing value: $flag"
      fi
      printf '%s' "${args[$((idx + 1))]}"
      return 0
    fi
    idx=$((idx + 1))
  done

  return 1
}

terraform_env_args() {
  local profile="$1"
  local region="$2"
  TF_ENV_ARGS=()
  if [[ -n "$profile" ]]; then
    TF_ENV_ARGS+=("AWS_PROFILE=$profile")
  fi
  if [[ -n "$region" ]]; then
    TF_ENV_ARGS+=("AWS_REGION=$region")
  fi
}

terraform_apply_live_e2e() {
  local terraform_dir="$1"
  local state_file="$2"
  local tfvars_file="$3"
  local aws_profile="$4"
  local aws_region="$5"

  terraform_env_args "$aws_profile" "$aws_region"
  env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform -chdir="$terraform_dir" init -input=false >/dev/null
  env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
    -chdir="$terraform_dir" \
    apply \
    -input=false \
    -auto-approve \
    -state="$state_file" \
    -var-file="$tfvars_file"
}

terraform_destroy_live_e2e() {
  local terraform_dir="$1"
  local state_file="$2"
  local tfvars_file="$3"
  local aws_profile="$4"
  local aws_region="$5"

  if [[ ! -f "$state_file" || ! -f "$tfvars_file" ]]; then
    log "terraform state or tfvars missing; nothing to destroy"
    return 0
  fi

  terraform_env_args "$aws_profile" "$aws_region"
  env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform -chdir="$terraform_dir" init -input=false >/dev/null
  env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
    -chdir="$terraform_dir" \
    destroy \
    -input=false \
    -auto-approve \
    -state="$state_file" \
    -var-file="$tfvars_file"
}

cleanup_trap() {
  if [[ "$cleanup_enabled" != "true" ]]; then
    return 0
  fi

  local infra_dir state_file tfvars_file
  infra_dir="$cleanup_workdir/infra"
  state_file="$infra_dir/terraform.tfstate"
  tfvars_file="$infra_dir/terraform.tfvars.json"

  log "cleanup trap: destroying live e2e infrastructure"
  if ! terraform_destroy_live_e2e "$cleanup_terraform_dir" "$state_file" "$tfvars_file" "$cleanup_aws_profile" "$cleanup_aws_region"; then
    log "cleanup trap destroy failed (manual cleanup may be required)"
  fi
}

wait_for_ssh() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ConnectTimeout=10
    -o BatchMode=yes
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  local attempt
  for attempt in $(seq 1 90); do
    if ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" 'echo ready' >/dev/null 2>&1; then
      log "ssh reachable: $ssh_user@$ssh_host"
      return 0
    fi
    sleep 10
  done
  die "timed out waiting for ssh connectivity to $ssh_user@$ssh_host"
}

remote_prepare_runner() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local repo_commit="$4"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  local remote_script
  remote_script="$(build_remote_prepare_script "$repo_commit")"

  ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" "bash -lc $(printf '%q' "$remote_script")"
}

remote_prepare_operator_host() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local repo_commit="$4"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  local remote_script
  remote_script="$(build_remote_operator_prepare_script "$repo_commit")"

  ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" "bash -lc $(printf '%q' "$remote_script")"
}

wait_for_shared_connectivity_from_runner() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local shared_postgres_host="$4"
  local shared_postgres_port="$5"
  local shared_kafka_brokers="$6"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  local remote_script
  remote_script="$(
    build_runner_shared_probe_script \
      "$shared_postgres_host" \
      "$shared_postgres_port" \
      "$shared_kafka_brokers"
  )"

  local attempt
  for attempt in $(seq 1 3); do
    log "checking shared services connectivity from runner (attempt $attempt/3)"
    if ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" "bash -lc $(printf '%q' "$remote_script")"; then
      return 0
    fi
    if [[ $attempt -lt 3 ]]; then
      sleep 5
    fi
  done

  return 1
}

build_remote_prepare_script() {
  local repo_commit="$1"
  cat <<EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if command -v cloud-init >/dev/null 2>&1; then
  sudo cloud-init status --wait || true
fi

run_apt_with_retry() {
  local attempt
  for attempt in \$(seq 1 30); do
    if sudo apt-get "\$@"; then
      return 0
    fi
    if [[ \$attempt -lt 30 ]]; then
      sleep 5
    fi
  done
  return 1
}

dump_boundless_failure_context() {
  local install_dir
  local generated_file

  install_dir="\$(ls -dt /tmp/cargo-install* 2>/dev/null | head -n1 || true)"
  if [[ -z "\$install_dir" ]]; then
    echo "boundless diagnostics: no /tmp/cargo-install* directory found"
    return 0
  fi

  generated_file="\$(find "\$install_dir" -type f -name 'boundless_market_generated.rs' | head -n1 || true)"
  if [[ -n "\$generated_file" && -f "\$generated_file" ]]; then
    echo "boundless diagnostics: generated file: \$generated_file"
    if command -v rg >/dev/null 2>&1; then
      rg -n "alloy::sol!|enum|library|interface" "\$generated_file" | tail -n 40 || true
    fi
    echo "boundless diagnostics: generated file tail"
    tail -n 80 "\$generated_file" || true
  else
    echo "boundless diagnostics: generated file not found under \$install_dir"
  fi
}

run_with_retry() {
  local attempt
  for attempt in \$(seq 1 3); do
    if "\$@"; then
      return 0
    fi
    if [[ "\$*" == *"cargo +1.91.1 install"* && "\$*" == *"boundless-cli"* ]]; then
      dump_boundless_failure_context || true
    fi
    if [[ \$attempt -lt 3 ]]; then
      rm -rf /tmp/cargo-install* || true
      sleep 5
    fi
  done
  return 1
}

run_apt_with_retry update -y
run_apt_with_retry install -y build-essential pkg-config libssl-dev jq curl git unzip ca-certificates rsync age golang-go tar

if [[ ! -d "\$HOME/.cargo" ]]; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
fi

export PATH="\$HOME/.cargo/bin:\$HOME/.foundry/bin:\$HOME/.risc0/bin:\$PATH"
if ! command -v foundryup >/dev/null 2>&1; then
  curl -L https://foundry.paradigm.xyz | bash
fi
foundryup

# Keep this pinned to the release branch documented for mainnet requestors.
run_with_retry rustup toolchain install 1.91.1 --profile minimal
run_with_retry rustup default 1.91.1
rustc --version
boundless_cli_target_version="1.2.0"
boundless_ref_tag="v1.2.1"
boundless_release_branch="release-1.2"
boundless_source_dir="/tmp/boundless-cli-release-1.2"
boundless_version_output=""
if command -v boundless >/dev/null 2>&1; then
  boundless_version_output="\$(boundless --version 2>/dev/null || true)"
fi
prepare_boundless_release_source() {
  local boundless_market_build_rs

  if [[ -d "\$boundless_source_dir/.git" ]]; then
    git -C "\$boundless_source_dir" fetch --depth 1 origin "\$boundless_release_branch"
    git -C "\$boundless_source_dir" checkout --force FETCH_HEAD
  else
    git clone --depth 1 --branch "\$boundless_release_branch" https://github.com/boundless-xyz/boundless "\$boundless_source_dir"
  fi

  boundless_market_build_rs="\$boundless_source_dir/crates/boundless-market/build.rs"
  if [[ ! -f "\$boundless_market_build_rs" ]]; then
    echo "boundless-market build script missing: \$boundless_market_build_rs" >&2
    return 1
  fi

  if ! grep -q "__BOUNDLESS_DUMMY__" "\$boundless_market_build_rs"; then
    perl -0pi -e 's/\{combined_sol_contents\}/\{combined_sol_contents\}\n            enum __BOUNDLESS_DUMMY__ {{ __BOUNDLESS_DUMMY_VALUE__ }}/s' "\$boundless_market_build_rs"
  fi
  if ! grep -q "__BOUNDLESS_DUMMY__" "\$boundless_market_build_rs"; then
    echo "failed to patch boundless market build script: \$boundless_market_build_rs" >&2
    return 1
  fi
}
install_boundless_cli() {
  if run_with_retry cargo +1.91.1 install boundless-cli --version "\$boundless_cli_target_version" --locked --force; then
    return 0
  fi
  echo "boundless-cli \$boundless_cli_target_version is unavailable on crates.io; falling back to git tag \$boundless_ref_tag"
  if run_with_retry cargo +1.91.1 install boundless-cli --git https://github.com/boundless-xyz/boundless --tag "\$boundless_ref_tag" --locked --force; then
    return 0
  fi
  echo "boundless-cli \$boundless_cli_target_version install from git tag failed; falling back to branch \$boundless_release_branch with parser workaround"
  prepare_boundless_release_source
  run_with_retry cargo +1.91.1 install --path "\$boundless_source_dir/crates/boundless-cli" --locked --force
}
if [[ "\$boundless_version_output" == *"boundless-cli \$boundless_cli_target_version"* ]]; then
  echo "boundless-cli already installed at target version; skipping reinstall"
else
  install_boundless_cli
fi
boundless --version

if ! command -v rzup >/dev/null 2>&1; then
  echo "installing rzup for risc0 toolchain"
  run_with_retry bash -lc "curl -sSfL https://risczero.com/install | bash"
fi
if ! command -v rzup >/dev/null 2>&1; then
  echo "rzup not found after install attempt" >&2
  exit 1
fi
run_with_retry rzup install
if ! command -v r0vm >/dev/null 2>&1; then
  echo "r0vm not found after rzup install" >&2
  exit 1
fi
r0vm --version

if [[ ! -d "\$HOME/intents-juno/.git" ]]; then
  git clone https://github.com/juno-intents/intents-juno.git "\$HOME/intents-juno"
fi
cd "\$HOME/intents-juno"
git fetch --tags origin
git checkout ${repo_commit}
git submodule update --init --recursive
mkdir -p .ci/secrets
chmod 700 .ci/secrets
EOF
}

build_remote_operator_prepare_script() {
  local repo_commit="$1"
  cat <<EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

if command -v cloud-init >/dev/null 2>&1; then
  sudo cloud-init status --wait || true
fi

run_apt_with_retry() {
  local attempt
  for attempt in \$(seq 1 30); do
    if sudo apt-get "\$@"; then
      return 0
    fi
    if [[ \$attempt -lt 30 ]]; then
      sleep 5
    fi
  done
  return 1
}

run_apt_with_retry update -y
run_apt_with_retry install -y build-essential pkg-config libssl-dev jq curl git unzip ca-certificates rsync age golang-go tar

if [[ ! -d "\$HOME/intents-juno/.git" ]]; then
  git clone https://github.com/juno-intents/intents-juno.git "\$HOME/intents-juno"
fi
cd "\$HOME/intents-juno"
git fetch --tags origin
git checkout ${repo_commit}
git submodule update --init --recursive
EOF
}

build_runner_shared_probe_script() {
  local shared_postgres_host="$1"
  local shared_postgres_port="$2"
  local shared_kafka_brokers="$3"

  cat <<EOF
set -euo pipefail
IFS=',' read -r -a broker_list <<<'${shared_kafka_brokers}'
if [[ \${#broker_list[@]} -eq 0 ]]; then
  echo "no kafka brokers provided by terraform output" >&2
  exit 1
fi

for attempt in \$(seq 1 120); do
  postgres_ready="false"
  kafka_ready="true"
  if timeout 2 bash -lc '</dev/tcp/${shared_postgres_host}/${shared_postgres_port}' >/dev/null 2>&1; then
    postgres_ready="true"
  fi

  for broker in "\${broker_list[@]}"; do
    broker="\${broker//[[:space:]]/}"
    [[ -n "\$broker" ]] || continue
    broker_host="\${broker%%:*}"
    broker_port="\${broker##*:}"
    if [[ -z "\$broker_host" || -z "\$broker_port" || "\$broker_host" == "\$broker_port" ]]; then
      kafka_ready="false"
      break
    fi
    if ! timeout 2 bash -lc "</dev/tcp/\${broker_host}/\${broker_port}" >/dev/null 2>&1; then
      kafka_ready="false"
      break
    fi
  done

  if [[ "\$postgres_ready" == "true" && "\$kafka_ready" == "true" ]]; then
    echo "shared services reachable from runner"
    exit 0
  fi
  if [[ \$attempt -lt 120 ]]; then
    sleep 2
  fi
done

echo "timed out waiting for shared services connectivity from runner (postgres=${shared_postgres_host}:${shared_postgres_port}, kafka=${shared_kafka_brokers})" >&2
exit 1
EOF
}

copy_remote_secret_file() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local local_file="$4"
  local remote_file="$5"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  scp "${ssh_opts[@]}" "$local_file" "$ssh_user@$ssh_host:$remote_file"
  ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" "chmod 600 $(printf '%q' "$remote_file")"
}

run_distributed_dkg_backup_restore() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local runner_public_ip="$3"
  local remote_repo="$4"
  local remote_workdir="$5"
  local repo_commit="$6"
  local operator_count="$7"
  local threshold="$8"
  local operator_base_port="$9"
  local release_tag="${10}"
  local dkg_summary_remote_path="${11}"
  local dkg_summary_local_path="${12}"
  local operator_public_ips_csv="${13}"
  local operator_private_ips_csv="${14}"
  local dkg_kms_key_arn="${15}"
  local dkg_s3_bucket="${16}"
  local dkg_s3_key_prefix="${17}"
  local aws_region="${18}"

  local -a ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  local -a operator_public_ips=()
  local -a operator_private_ips=()
  if [[ -n "$operator_public_ips_csv" ]]; then
    IFS=',' read -r -a operator_public_ips <<<"$operator_public_ips_csv"
  fi
  if [[ -n "$operator_private_ips_csv" ]]; then
    IFS=',' read -r -a operator_private_ips <<<"$operator_private_ips_csv"
  fi

  (( ${#operator_public_ips[@]} == operator_count )) || die "operator public ip count mismatch: expected=$operator_count got=${#operator_public_ips[@]}"
  (( ${#operator_private_ips[@]} == operator_count )) || die "operator private ip count mismatch: expected=$operator_count got=${#operator_private_ips[@]}"

  local idx op_index op_public_ip op_private_ip op_port
  for ((idx = 0; idx < operator_count; idx++)); do
    op_index=$((idx + 1))
    op_public_ip="${operator_public_ips[$idx]}"
    log "preparing operator host op${op_index} at ${op_public_ip}"
    wait_for_ssh "$ssh_private_key" "$ssh_user" "$op_public_ip"
    remote_prepare_operator_host "$ssh_private_key" "$ssh_user" "$op_public_ip" "$repo_commit"
  done

  local private_ip_joined
  private_ip_joined="$(shell_join "${operator_private_ips[@]}")"
  local runner_init_script
  runner_init_script="$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export JUNO_DKG_ALLOW_INSECURE_NETWORK=1
dkg_root="$remote_workdir/dkg-distributed"
rm -rf "\$dkg_root"
mkdir -p "\$dkg_root/operators" "\$dkg_root/reports"

operator_private_ips=($private_ip_joined)
for ((i = 1; i <= ${operator_count}; i++)); do
  op_dir="\$dkg_root/operators/op\${i}"
  key_file="\$op_dir/operator.key"
  meta_json="\$op_dir/operator-meta.json"
  registration_json="\$op_dir/registration.json"
  port=\$(( ${operator_base_port} + i - 1 ))
  endpoint="https://\${operator_private_ips[\$((i - 1))]}:\${port}"

  mkdir -p "\$op_dir"
  go run ./cmd/operator-keygen -private-key-path "\$key_file" >"\$meta_json"

  operator_id="\$(jq -r '.operator_id' "\$meta_json")"
  fee_recipient="\$(jq -r '.fee_recipient' "\$meta_json")"
  jq -n \\
    --arg operator_id "\$operator_id" \\
    --arg fee_recipient "\$fee_recipient" \\
    --arg grpc_endpoint "\$endpoint" \\
    '{
      operator_id: \$operator_id,
      fee_recipient: \$fee_recipient,
      grpc_endpoint: \$grpc_endpoint
    }' >"\$registration_json"
done

coordinator_init_args=(
  --workdir "\$dkg_root/coordinator"
  --network testnet
  --threshold "${threshold}"
  --max-signers "${operator_count}"
  --release-tag "${release_tag}"
)
for ((i = 1; i <= ${operator_count}; i++)); do
  coordinator_init_args+=(--registration-file "\$dkg_root/operators/op\${i}/registration.json")
done
deploy/operators/dkg/coordinator.sh init "\${coordinator_init_args[@]}"

for ((i = 1; i <= ${operator_count}; i++)); do
  op_dir="\$dkg_root/operators/op\${i}"
  operator_id="\$(jq -r '.operator_id' "\$op_dir/operator-meta.json")"
  slug="\$(printf '%s' "\$operator_id" | tr -cs '[:alnum:]_.-' '_' | sed -e 's/^_\\+//' -e 's/_\\+\$//')"
  if [[ -z "\$slug" ]]; then
    slug="value"
  fi
  bundle_path="\$(find "\$dkg_root/coordinator/bundles" -maxdepth 1 -type f -name "*_\${slug}.tar.gz" | head -n 1)"
  if [[ -z "\$bundle_path" ]]; then
    echo "bundle not found for operator \${operator_id}" >&2
    exit 1
  fi
  cp "\$bundle_path" "\$op_dir/bundle.tar.gz"
done
EOF
)"

  log "initializing distributed dkg coordinator and operator bundles on runner"
  ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" "bash -lc $(printf '%q' "$runner_init_script")"

  local staged_bundle_dir
  staged_bundle_dir="$(mktemp -d)"

  for ((idx = 0; idx < operator_count; idx++)); do
    op_index=$((idx + 1))
    op_public_ip="${operator_public_ips[$idx]}"
    op_port=$((operator_base_port + op_index - 1))

    local bundle_local bundle_remote operator_root_remote
    bundle_local="$staged_bundle_dir/op${op_index}-bundle.tar.gz"
    bundle_remote="$remote_workdir/dkg-distributed/operators/op${op_index}/bundle.tar.gz"
    operator_root_remote="$remote_workdir/dkg-distributed/operators/op${op_index}"

    scp "${ssh_opts[@]}" "$ssh_user@$runner_public_ip:$bundle_remote" "$bundle_local"
    ssh "${ssh_opts[@]}" "$ssh_user@$op_public_ip" "mkdir -p $(printf '%q' "$operator_root_remote")"
    scp "${ssh_opts[@]}" "$bundle_local" "$ssh_user@$op_public_ip:$bundle_remote"

    local start_operator_script
    start_operator_script="$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export JUNO_DKG_ALLOW_INSECURE_NETWORK=1
op_root="$operator_root_remote"
runtime_dir="\$op_root/runtime"
deploy/operators/dkg/operator.sh stop --workdir "\$runtime_dir" >/dev/null 2>&1 || true
rm -rf "\$runtime_dir"
deploy/operators/dkg/operator.sh run \
  --bundle "\$op_root/bundle.tar.gz" \
  --workdir "\$runtime_dir" \
  --release-tag "${release_tag}" \
  --daemon
EOF
)"

    log "starting operator daemon op${op_index} on ${op_public_ip}:${op_port}"
    ssh "${ssh_opts[@]}" "$ssh_user@$op_public_ip" "bash -lc $(printf '%q' "$start_operator_script")"
  done

  local coordinator_workdir completion_report
  coordinator_workdir="$remote_workdir/dkg-distributed/coordinator"
  completion_report="$coordinator_workdir/reports/test-completiton.json"
  local runner_execute_ceremony_script
  runner_execute_ceremony_script="$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export JUNO_DKG_ALLOW_INSECURE_NETWORK=1
deploy/operators/dkg/coordinator.sh preflight --workdir "$coordinator_workdir" --release-tag "${release_tag}"
deploy/operators/dkg/coordinator.sh run --workdir "$coordinator_workdir" --release-tag "${release_tag}"
deploy/operators/dkg/test-completiton.sh run \
  --workdir "$coordinator_workdir" \
  --skip-resume \
  --release-tag "${release_tag}" \
  --output "$completion_report"
EOF
)"
  log "running distributed dkg ceremony from runner coordinator"
  ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" "bash -lc $(printf '%q' "$runner_execute_ceremony_script")"

  for ((idx = 0; idx < operator_count; idx++)); do
    op_index=$((idx + 1))
    op_public_ip="${operator_public_ips[$idx]}"

    local operator_work_root
    operator_work_root="$remote_workdir/dkg-distributed/operators/op${op_index}"
    local backup_restore_script
    backup_restore_script="$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export JUNO_DKG_ALLOW_INSECURE_NETWORK=1
op_root="$operator_work_root"
runtime_dir="\$op_root/runtime"
age_identity="\$op_root/backup/age-identity.txt"
age_payload="\$op_root/backup/age-recipient.json"
age_backup="\$op_root/exports/keypackage-backup.json"
backup_zip="\$op_root/backup-packages/dkg-backup.zip"
kms_receipt="\$op_root/exports/kms-export-receipt.json"

mkdir -p "\$op_root/backup" "\$op_root/exports" "\$op_root/backup-packages"

deploy/operators/dkg/operator-export-kms.sh age-recipient \
  --identity-file "\$age_identity" \
  --output "\$age_payload"

age_recipient="\$(jq -r '.age_recipient' "\$age_payload")"
deploy/operators/dkg/operator-export-kms.sh backup-age \
  --workdir "\$runtime_dir" \
  --release-tag "${release_tag}" \
  --age-recipient "\$age_recipient" \
  --out "\$age_backup"

deploy/operators/dkg/backup-package.sh create \
  --workdir "\$runtime_dir" \
  --age-identity-file "\$age_identity" \
  --age-backup-file "\$age_backup" \
  --admin-config "\$runtime_dir/bundle/admin-config.json" \
  --output "\$backup_zip" \
  --force

deploy/operators/dkg/operator.sh stop --workdir "\$runtime_dir" >/dev/null 2>&1 || true
rm -rf "\$runtime_dir"

deploy/operators/dkg/backup-package.sh restore \
  --package "\$backup_zip" \
  --workdir "\$runtime_dir" \
  --force

deploy/operators/dkg/operator.sh run \
  --bundle "\$runtime_dir/bundle" \
  --workdir "\$runtime_dir" \
  --release-tag "${release_tag}" \
  --daemon

deploy/operators/dkg/operator-export-kms.sh export \
  --workdir "\$runtime_dir" \
  --release-tag "${release_tag}" \
  --kms-key-id "${dkg_kms_key_arn}" \
  --s3-bucket "${dkg_s3_bucket}" \
  --s3-key-prefix "${dkg_s3_key_prefix}" \
  --s3-sse-kms-key-id "${dkg_kms_key_arn}" \
  --aws-region "${aws_region}" \
  --skip-aws-preflight >"\$kms_receipt"

deploy/operators/dkg/operator.sh status --workdir "\$runtime_dir" >"\$op_root/status.json"
EOF
)"

    log "running backup/restore verification on operator host op${op_index}"
    ssh "${ssh_opts[@]}" "$ssh_user@$op_public_ip" "bash -lc $(printf '%q' "$backup_restore_script")"
  done

  local operators_json
  operators_json='[]'
  for ((idx = 0; idx < operator_count; idx++)); do
    op_index=$((idx + 1))
    op_public_ip="${operator_public_ips[$idx]}"
    op_private_ip="${operator_private_ips[$idx]}"
    op_port=$((operator_base_port + op_index - 1))

    local operator_id status_json
    operator_id="$(
      ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" \
        "jq -r '.operator_id // empty' $(printf '%q' "$remote_workdir/dkg-distributed/operators/op${op_index}/operator-meta.json")"
    )"
    [[ -n "$operator_id" ]] || die "missing operator id for op${op_index}"

    status_json="$(
      ssh "${ssh_opts[@]}" "$ssh_user@$op_public_ip" \
        "cat $(printf '%q' "$remote_workdir/dkg-distributed/operators/op${op_index}/status.json")"
    )"
    if [[ "$(printf '%s' "$status_json" | jq -r '.running')" != "true" ]]; then
      die "restored distributed operator is not running: op${op_index}"
    fi

    local op_json
    op_json="$(jq -n \
      --argjson index "$op_index" \
      --arg operator_id "$operator_id" \
      --arg operator_key_file "$remote_workdir/dkg-distributed/operators/op${op_index}/operator.key" \
      --arg registration_file "$remote_workdir/dkg-distributed/operators/op${op_index}/registration.json" \
      --arg endpoint "https://${op_private_ip}:${op_port}" \
      --arg runtime_dir "$remote_workdir/dkg-distributed/operators/op${op_index}/runtime" \
      --arg backup_package "$remote_workdir/dkg-distributed/operators/op${op_index}/backup-packages/dkg-backup.zip" \
      --arg kms_receipt "$remote_workdir/dkg-distributed/operators/op${op_index}/exports/kms-export-receipt.json" \
      --argjson status "$status_json" \
      '{
        index: $index,
        operator_id: $operator_id,
        operator_key_file: $operator_key_file,
        registration_file: $registration_file,
        endpoint: $endpoint,
        runtime_dir: $runtime_dir,
        backup_package: $backup_package,
        kms_receipt: $kms_receipt,
        status: $status
      }')"
    operators_json="$(jq --argjson op "$op_json" '. + [$op]' <<<"$operators_json")"
  done

  ensure_dir "$(dirname "$dkg_summary_local_path")"
  jq -n \
    --arg generated_at "$(timestamp_utc)" \
    --arg workdir "$remote_workdir/dkg-distributed" \
    --arg coordinator_workdir "$coordinator_workdir" \
    --arg completion_report "$completion_report" \
    --arg network "testnet" \
    --arg kms_key_arn "$dkg_kms_key_arn" \
    --arg kms_s3_bucket "$dkg_s3_bucket" \
    --arg kms_s3_key_prefix "$dkg_s3_key_prefix" \
    --argjson operator_count "$operator_count" \
    --argjson threshold "$threshold" \
    --argjson operators "$operators_json" \
    '{
      summary_version: 1,
      generated_at: $generated_at,
      workdir: $workdir,
      coordinator_workdir: $coordinator_workdir,
      completion_report: $completion_report,
      network: $network,
      operator_count: $operator_count,
      threshold: $threshold,
      dkg_secrets: {
        kms_key_arn: $kms_key_arn,
        s3_bucket: $kms_s3_bucket,
        s3_key_prefix: $kms_s3_key_prefix
      },
      operators: $operators
    }' >"$dkg_summary_local_path"

  ssh "${ssh_opts[@]}" "$ssh_user@$runner_public_ip" "mkdir -p $(printf '%q' "$(dirname "$dkg_summary_remote_path")")"
  scp "${ssh_opts[@]}" "$dkg_summary_local_path" "$ssh_user@$runner_public_ip:$dkg_summary_remote_path"
  rm -rf "$staged_bundle_dir"
}

command_cleanup() {
  shift || true

  local workdir="$REPO_ROOT/tmp/aws-live-e2e"
  local terraform_dir="$REPO_ROOT/deploy/shared/terraform/live-e2e"
  local aws_profile=""
  local aws_region=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --terraform-dir)
        [[ $# -ge 2 ]] || die "missing value for --terraform-dir"
        terraform_dir="$2"
        shift 2
        ;;
      --aws-profile)
        [[ $# -ge 2 ]] || die "missing value for --aws-profile"
        aws_profile="$2"
        shift 2
        ;;
      --aws-region)
        [[ $# -ge 2 ]] || die "missing value for --aws-region"
        aws_region="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for cleanup: $1"
        ;;
    esac
  done

  local infra_dir state_file tfvars_file
  infra_dir="$workdir/infra"
  state_file="$infra_dir/terraform.tfstate"
  tfvars_file="$infra_dir/terraform.tfvars.json"

  if [[ ! -f "$tfvars_file" ]]; then
    log "cleanup: tfvars file not found; nothing to destroy"
    return 0
  fi

  if [[ -z "$aws_region" ]]; then
    aws_region="$(jq -r '.aws_region // empty' "$tfvars_file")"
  fi

  terraform_destroy_live_e2e "$terraform_dir" "$state_file" "$tfvars_file" "$aws_profile" "$aws_region"
}

command_run() {
  shift || true

  local workdir="$REPO_ROOT/tmp/aws-live-e2e"
  local terraform_dir="$REPO_ROOT/deploy/shared/terraform/live-e2e"
  local aws_region=""
  local aws_profile=""
  local aws_name_prefix="juno-live-e2e"
  local aws_instance_type="c7i.4xlarge"
  local runner_ami_id=""
  local aws_root_volume_gb="200"
  local operator_instance_count="5"
  local operator_instance_type="c7i.large"
  local operator_ami_id=""
  local operator_root_volume_gb="100"
  local shared_ami_id=""
  local operator_base_port="18443"
  local dkg_s3_key_prefix="dkg/keypackages"
  local dkg_release_tag="${JUNO_DKG_VERSION_DEFAULT:-v0.1.0}"
  local operator_count_explicit="false"
  local operator_base_port_explicit="false"
  local ssh_allowed_cidr=""
  local base_funder_key_file=""
  local juno_funder_key_file=""
  local juno_rpc_user_file=""
  local juno_rpc_pass_file=""
  local juno_scan_bearer_token_file=""
  local boundless_requestor_key_file=""
  local with_shared_services="true"
  local shared_postgres_user="postgres"
  local shared_postgres_db="intents_e2e"
  local shared_postgres_port="5432"
  local shared_kafka_port="9092"
  local keep_infra="false"
  local -a e2e_args=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --terraform-dir)
        [[ $# -ge 2 ]] || die "missing value for --terraform-dir"
        terraform_dir="$2"
        shift 2
        ;;
      --aws-region)
        [[ $# -ge 2 ]] || die "missing value for --aws-region"
        aws_region="$2"
        shift 2
        ;;
      --aws-profile)
        [[ $# -ge 2 ]] || die "missing value for --aws-profile"
        aws_profile="$2"
        shift 2
        ;;
      --aws-name-prefix)
        [[ $# -ge 2 ]] || die "missing value for --aws-name-prefix"
        aws_name_prefix="$2"
        shift 2
        ;;
      --aws-instance-type)
        [[ $# -ge 2 ]] || die "missing value for --aws-instance-type"
        aws_instance_type="$2"
        shift 2
        ;;
      --runner-ami-id)
        [[ $# -ge 2 ]] || die "missing value for --runner-ami-id"
        runner_ami_id="$2"
        shift 2
        ;;
      --aws-root-volume-gb)
        [[ $# -ge 2 ]] || die "missing value for --aws-root-volume-gb"
        aws_root_volume_gb="$2"
        shift 2
        ;;
      --operator-instance-count)
        [[ $# -ge 2 ]] || die "missing value for --operator-instance-count"
        operator_instance_count="$2"
        operator_count_explicit="true"
        shift 2
        ;;
      --operator-instance-type)
        [[ $# -ge 2 ]] || die "missing value for --operator-instance-type"
        operator_instance_type="$2"
        shift 2
        ;;
      --operator-ami-id)
        [[ $# -ge 2 ]] || die "missing value for --operator-ami-id"
        operator_ami_id="$2"
        shift 2
        ;;
      --operator-root-volume-gb)
        [[ $# -ge 2 ]] || die "missing value for --operator-root-volume-gb"
        operator_root_volume_gb="$2"
        shift 2
        ;;
      --shared-ami-id)
        [[ $# -ge 2 ]] || die "missing value for --shared-ami-id"
        shared_ami_id="$2"
        shift 2
        ;;
      --operator-base-port)
        [[ $# -ge 2 ]] || die "missing value for --operator-base-port"
        operator_base_port="$2"
        operator_base_port_explicit="true"
        shift 2
        ;;
      --dkg-s3-key-prefix)
        [[ $# -ge 2 ]] || die "missing value for --dkg-s3-key-prefix"
        dkg_s3_key_prefix="$2"
        shift 2
        ;;
      --dkg-release-tag)
        [[ $# -ge 2 ]] || die "missing value for --dkg-release-tag"
        dkg_release_tag="$2"
        shift 2
        ;;
      --ssh-allowed-cidr)
        [[ $# -ge 2 ]] || die "missing value for --ssh-allowed-cidr"
        ssh_allowed_cidr="$2"
        shift 2
        ;;
      --base-funder-key-file)
        [[ $# -ge 2 ]] || die "missing value for --base-funder-key-file"
        base_funder_key_file="$2"
        shift 2
        ;;
      --juno-funder-key-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-funder-key-file"
        juno_funder_key_file="$2"
        shift 2
        ;;
      --juno-rpc-user-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-rpc-user-file"
        juno_rpc_user_file="$2"
        shift 2
        ;;
      --juno-rpc-pass-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-rpc-pass-file"
        juno_rpc_pass_file="$2"
        shift 2
        ;;
      --juno-scan-bearer-token-file)
        [[ $# -ge 2 ]] || die "missing value for --juno-scan-bearer-token-file"
        juno_scan_bearer_token_file="$2"
        shift 2
        ;;
      --boundless-requestor-key-file)
        [[ $# -ge 2 ]] || die "missing value for --boundless-requestor-key-file"
        boundless_requestor_key_file="$2"
        shift 2
        ;;
      --without-shared-services)
        with_shared_services="false"
        shift
        ;;
      --shared-postgres-user)
        [[ $# -ge 2 ]] || die "missing value for --shared-postgres-user"
        shared_postgres_user="$2"
        shift 2
        ;;
      --shared-postgres-db)
        [[ $# -ge 2 ]] || die "missing value for --shared-postgres-db"
        shared_postgres_db="$2"
        shift 2
        ;;
      --shared-postgres-port)
        [[ $# -ge 2 ]] || die "missing value for --shared-postgres-port"
        shared_postgres_port="$2"
        shift 2
        ;;
      --shared-kafka-port)
        [[ $# -ge 2 ]] || die "missing value for --shared-kafka-port"
        shared_kafka_port="$2"
        shift 2
        ;;
      --keep-infra)
        keep_infra="true"
        shift
        ;;
      --)
        shift
        e2e_args=("$@")
        break
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for run: $1"
        ;;
    esac
  done

  [[ -n "$aws_region" ]] || die "--aws-region is required"
  [[ -n "$base_funder_key_file" ]] || die "--base-funder-key-file is required"
  [[ -n "$juno_funder_key_file" ]] || die "--juno-funder-key-file is required"
  [[ -n "$juno_rpc_user_file" ]] || die "--juno-rpc-user-file is required"
  [[ -n "$juno_rpc_pass_file" ]] || die "--juno-rpc-pass-file is required"
  [[ -f "$base_funder_key_file" ]] || die "base funder key file not found: $base_funder_key_file"
  [[ -f "$juno_funder_key_file" ]] || die "juno funder key file not found: $juno_funder_key_file"
  [[ -f "$juno_rpc_user_file" ]] || die "juno rpc user file not found: $juno_rpc_user_file"
  [[ -f "$juno_rpc_pass_file" ]] || die "juno rpc pass file not found: $juno_rpc_pass_file"
  if [[ -n "$juno_scan_bearer_token_file" && ! -f "$juno_scan_bearer_token_file" ]]; then
    die "juno scan bearer token file not found: $juno_scan_bearer_token_file"
  fi
  [[ "$operator_instance_count" =~ ^[0-9]+$ ]] || die "--operator-instance-count must be numeric"
  [[ "$operator_root_volume_gb" =~ ^[0-9]+$ ]] || die "--operator-root-volume-gb must be numeric"
  [[ "$operator_base_port" =~ ^[0-9]+$ ]] || die "--operator-base-port must be numeric"
  (( operator_instance_count >= 1 )) || die "--operator-instance-count must be >= 1"
  (( operator_base_port >= 1 && operator_base_port <= 65535 )) || die "--operator-base-port must be in [1, 65535]"
  [[ "$shared_postgres_port" =~ ^[0-9]+$ ]] || die "--shared-postgres-port must be numeric"
  [[ "$shared_kafka_port" =~ ^[0-9]+$ ]] || die "--shared-kafka-port must be numeric"
  [[ -n "$shared_postgres_user" ]] || die "--shared-postgres-user must not be empty"
  [[ -n "$shared_postgres_db" ]] || die "--shared-postgres-db must not be empty"
  [[ -n "$dkg_s3_key_prefix" ]] || die "--dkg-s3-key-prefix must not be empty"
  if [[ -n "$runner_ami_id" && ! "$runner_ami_id" =~ ^ami-[a-zA-Z0-9]+$ ]]; then
    die "--runner-ami-id must look like an AMI id (ami-...)"
  fi
  if [[ -n "$operator_ami_id" && ! "$operator_ami_id" =~ ^ami-[a-zA-Z0-9]+$ ]]; then
    die "--operator-ami-id must look like an AMI id (ami-...)"
  fi
  if [[ -n "$shared_ami_id" && ! "$shared_ami_id" =~ ^ami-[a-zA-Z0-9]+$ ]]; then
    die "--shared-ami-id must look like an AMI id (ami-...)"
  fi
  if [[ -n "$boundless_requestor_key_file" && ! -f "$boundless_requestor_key_file" ]]; then
    die "boundless requestor key file not found: $boundless_requestor_key_file"
  fi

  ensure_base_dependencies
  ensure_local_command terraform
  ensure_local_command aws
  ensure_local_command ssh
  ensure_local_command scp
  ensure_local_command git
  ensure_local_command ssh-keygen
  ensure_local_command openssl

  local dkg_threshold="3"
  local forwarded_operator_count=""
  local forwarded_operator_base_port=""
  local forwarded_threshold=""
  if forwarded_operator_count="$(forwarded_arg_value "--operator-count" "${e2e_args[@]}" 2>/dev/null)"; then
    [[ "$forwarded_operator_count" =~ ^[0-9]+$ ]] || die "forwarded --operator-count must be numeric"
    if [[ "$operator_count_explicit" == "true" && "$forwarded_operator_count" != "$operator_instance_count" ]]; then
      die "forwarded --operator-count ($forwarded_operator_count) conflicts with --operator-instance-count ($operator_instance_count)"
    fi
    operator_instance_count="$forwarded_operator_count"
  fi
  if forwarded_operator_base_port="$(forwarded_arg_value "--base-port" "${e2e_args[@]}" 2>/dev/null)"; then
    [[ "$forwarded_operator_base_port" =~ ^[0-9]+$ ]] || die "forwarded --base-port must be numeric"
    if [[ "$operator_base_port_explicit" == "true" && "$forwarded_operator_base_port" != "$operator_base_port" ]]; then
      die "forwarded --base-port ($forwarded_operator_base_port) conflicts with --operator-base-port ($operator_base_port)"
    fi
    operator_base_port="$forwarded_operator_base_port"
  fi
  if forwarded_threshold="$(forwarded_arg_value "--threshold" "${e2e_args[@]}" 2>/dev/null)"; then
    [[ "$forwarded_threshold" =~ ^[0-9]+$ ]] || die "forwarded --threshold must be numeric"
    dkg_threshold="$forwarded_threshold"
  fi
  (( dkg_threshold >= 2 )) || die "distributed dkg threshold must be >= 2"
  (( dkg_threshold <= operator_instance_count )) || die "distributed dkg threshold must be <= operator instance count"

  if [[ -z "$ssh_allowed_cidr" ]]; then
    local caller_ip
    caller_ip="$(curl -fsS https://checkip.amazonaws.com | tr -d '\r\n')"
    [[ "$caller_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "failed to detect caller IP"
    ssh_allowed_cidr="${caller_ip}/32"
  fi

  local infra_dir ssh_dir artifacts_dir
  infra_dir="$workdir/infra"
  ssh_dir="$workdir/ssh"
  artifacts_dir="$workdir/artifacts"
  ensure_dir "$infra_dir"
  ensure_dir "$ssh_dir"
  ensure_dir "$artifacts_dir"

  local ssh_key_private ssh_key_public
  ssh_key_private="$ssh_dir/id_ed25519"
  ssh_key_public="$ssh_dir/id_ed25519.pub"
  rm -f "$ssh_key_private" "$ssh_key_public"
  ssh-keygen -t ed25519 -N "" -f "$ssh_key_private" >/dev/null

  local deployment_id
  deployment_id="$(date -u +%Y%m%d%H%M%S)-$(openssl rand -hex 3)"
  local shared_postgres_password
  shared_postgres_password="$(openssl rand -hex 16)"

  local tfvars_file state_file
  tfvars_file="$infra_dir/terraform.tfvars.json"
  state_file="$infra_dir/terraform.tfstate"

  local provision_shared_services_json
  if [[ "$with_shared_services" == "true" ]]; then
    provision_shared_services_json="true"
  else
    provision_shared_services_json="false"
  fi

  jq -n \
    --arg aws_region "$aws_region" \
    --arg deployment_id "$deployment_id" \
    --arg name_prefix "$aws_name_prefix" \
    --arg instance_type "$aws_instance_type" \
    --arg runner_ami_id "$runner_ami_id" \
    --argjson root_volume_size_gb "$aws_root_volume_gb" \
    --argjson operator_instance_count "$operator_instance_count" \
    --arg operator_instance_type "$operator_instance_type" \
    --arg operator_ami_id "$operator_ami_id" \
    --argjson operator_root_volume_size_gb "$operator_root_volume_gb" \
    --arg shared_ami_id "$shared_ami_id" \
    --argjson operator_base_port "$operator_base_port" \
    --arg allowed_ssh_cidr "$ssh_allowed_cidr" \
    --arg ssh_public_key "$(cat "$ssh_key_public")" \
    --argjson provision_shared_services "$provision_shared_services_json" \
    --arg shared_postgres_user "$shared_postgres_user" \
    --arg shared_postgres_password "$shared_postgres_password" \
    --arg shared_postgres_db "$shared_postgres_db" \
    --argjson shared_postgres_port "$shared_postgres_port" \
    --argjson shared_kafka_port "$shared_kafka_port" \
    --arg dkg_s3_key_prefix "$dkg_s3_key_prefix" \
    '{
      aws_region: $aws_region,
      deployment_id: $deployment_id,
      name_prefix: $name_prefix,
      instance_type: $instance_type,
      runner_ami_id: $runner_ami_id,
      root_volume_size_gb: $root_volume_size_gb,
      operator_instance_count: $operator_instance_count,
      operator_instance_type: $operator_instance_type,
      operator_ami_id: $operator_ami_id,
      operator_root_volume_size_gb: $operator_root_volume_size_gb,
      shared_ami_id: $shared_ami_id,
      operator_base_port: $operator_base_port,
      allowed_ssh_cidr: $allowed_ssh_cidr,
      ssh_public_key: $ssh_public_key,
      provision_shared_services: $provision_shared_services,
      shared_postgres_user: $shared_postgres_user,
      shared_postgres_password: $shared_postgres_password,
      shared_postgres_db: $shared_postgres_db,
      shared_postgres_port: $shared_postgres_port,
      shared_kafka_port: $shared_kafka_port,
      dkg_s3_key_prefix: $dkg_s3_key_prefix
    }' >"$tfvars_file"

  cleanup_enabled="true"
  cleanup_workdir="$workdir"
  cleanup_terraform_dir="$terraform_dir"
  cleanup_aws_profile="$aws_profile"
  cleanup_aws_region="$aws_region"
  trap cleanup_trap EXIT

  log "provisioning AWS runner (deployment_id=$deployment_id)"
  terraform_apply_live_e2e "$terraform_dir" "$state_file" "$tfvars_file" "$aws_profile" "$aws_region"

  local runner_public_ip runner_ssh_user
  terraform_env_args "$aws_profile" "$aws_region"
  runner_public_ip="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -raw runner_public_ip
  )"
  runner_ssh_user="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -raw runner_ssh_user
  )"

  local shared_private_ip=""
  local shared_public_ip=""
  if [[ "$with_shared_services" == "true" ]]; then
    shared_private_ip="$(
      env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
        -chdir="$terraform_dir" \
        output \
        -state="$state_file" \
        -raw shared_private_ip
    )"
    [[ -n "$shared_private_ip" && "$shared_private_ip" != "null" ]] || die "shared services were requested but terraform output shared_private_ip is empty"
    shared_public_ip="$(
      env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
        -chdir="$terraform_dir" \
        output \
        -state="$state_file" \
        -raw shared_public_ip
    )"
    [[ -n "$shared_public_ip" && "$shared_public_ip" != "null" ]] || die "shared services were requested but terraform output shared_public_ip is empty"
  fi

  local operator_public_ips_json operator_private_ips_json
  operator_public_ips_json="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -json operator_public_ips
  )"
  operator_private_ips_json="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -json operator_private_ips
  )"

  local -a operator_public_ips=()
  local -a operator_private_ips=()
  mapfile -t operator_public_ips < <(jq -r '.[]' <<<"$operator_public_ips_json")
  mapfile -t operator_private_ips < <(jq -r '.[]' <<<"$operator_private_ips_json")
  (( ${#operator_public_ips[@]} == operator_instance_count )) || die "terraform operator_public_ips count mismatch: expected=$operator_instance_count got=${#operator_public_ips[@]}"
  (( ${#operator_private_ips[@]} == operator_instance_count )) || die "terraform operator_private_ips count mismatch: expected=$operator_instance_count got=${#operator_private_ips[@]}"

  local dkg_kms_key_arn dkg_s3_bucket dkg_s3_key_prefix_out
  dkg_kms_key_arn="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -raw dkg_kms_key_arn
  )"
  dkg_s3_bucket="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -raw dkg_s3_bucket
  )"
  dkg_s3_key_prefix_out="$(
    env "${TF_ENV_ARGS[@]}" TF_IN_AUTOMATION=1 terraform \
      -chdir="$terraform_dir" \
      output \
      -state="$state_file" \
      -raw dkg_s3_key_prefix
  )"
  [[ -n "$dkg_kms_key_arn" && "$dkg_kms_key_arn" != "null" ]] || die "terraform output dkg_kms_key_arn is empty"
  [[ -n "$dkg_s3_bucket" && "$dkg_s3_bucket" != "null" ]] || die "terraform output dkg_s3_bucket is empty"
  [[ -n "$dkg_s3_key_prefix_out" && "$dkg_s3_key_prefix_out" != "null" ]] || die "terraform output dkg_s3_key_prefix is empty"

  if [[ "$with_shared_services" == "true" ]]; then
    wait_for_ssh "$ssh_key_private" "$runner_ssh_user" "$shared_public_ip"
    if ! remote_prepare_shared_host \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$shared_public_ip" \
      "$shared_private_ip" \
      "$shared_postgres_user" \
      "$shared_postgres_password" \
      "$shared_postgres_db" \
      "$shared_postgres_port" \
      "$shared_kafka_port"; then
      die "failed to prepare shared services host"
    fi
  fi

  wait_for_ssh "$ssh_key_private" "$runner_ssh_user" "$runner_public_ip"

  local repo_commit
  repo_commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  log "preparing remote runner host"
  remote_prepare_runner "$ssh_key_private" "$runner_ssh_user" "$runner_public_ip" "$repo_commit"

  local remote_repo remote_workdir
  remote_repo="/home/${runner_ssh_user}/intents-juno"
  remote_workdir="/home/${runner_ssh_user}/testnet-e2e-live"

  local operator_public_ips_csv operator_private_ips_csv
  operator_public_ips_csv="$(IFS=,; printf '%s' "${operator_public_ips[*]}")"
  operator_private_ips_csv="$(IFS=,; printf '%s' "${operator_private_ips[*]}")"

  local dkg_summary_remote_path dkg_summary_local_path
  dkg_summary_remote_path="$remote_workdir/reports/dkg-summary.json"
  dkg_summary_local_path="$artifacts_dir/dkg-summary-distributed.json"

  run_distributed_dkg_backup_restore \
    "$ssh_key_private" \
    "$runner_ssh_user" \
    "$runner_public_ip" \
    "$remote_repo" \
    "$remote_workdir" \
    "$repo_commit" \
    "$operator_instance_count" \
    "$dkg_threshold" \
    "$operator_base_port" \
    "$dkg_release_tag" \
    "$dkg_summary_remote_path" \
    "$dkg_summary_local_path" \
    "$operator_public_ips_csv" \
    "$operator_private_ips_csv" \
    "$dkg_kms_key_arn" \
    "$dkg_s3_bucket" \
    "$dkg_s3_key_prefix_out" \
    "$aws_region"

  copy_remote_secret_file \
    "$ssh_key_private" \
    "$runner_ssh_user" \
    "$runner_public_ip" \
    "$base_funder_key_file" \
    "$remote_repo/.ci/secrets/base-funder.key"

  copy_remote_secret_file \
    "$ssh_key_private" \
    "$runner_ssh_user" \
    "$runner_public_ip" \
    "$juno_funder_key_file" \
    "$remote_repo/.ci/secrets/juno-funder.key"

  copy_remote_secret_file \
    "$ssh_key_private" \
    "$runner_ssh_user" \
    "$runner_public_ip" \
    "$juno_rpc_user_file" \
    "$remote_repo/.ci/secrets/juno-rpc-user.txt"

  copy_remote_secret_file \
    "$ssh_key_private" \
    "$runner_ssh_user" \
    "$runner_public_ip" \
    "$juno_rpc_pass_file" \
    "$remote_repo/.ci/secrets/juno-rpc-pass.txt"

  if [[ -n "$juno_scan_bearer_token_file" ]]; then
    copy_remote_secret_file \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$juno_scan_bearer_token_file" \
      "$remote_repo/.ci/secrets/juno-scan-bearer.txt"
  fi

  if [[ -n "$boundless_requestor_key_file" ]]; then
    copy_remote_secret_file \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$boundless_requestor_key_file" \
      "$remote_repo/.ci/secrets/boundless-requestor.key"
  fi

  local -a remote_args
  remote_args=(
    run
    --workdir "$remote_workdir"
    --dkg-summary-path "$dkg_summary_remote_path"
    --base-funder-key-file ".ci/secrets/base-funder.key"
    --output "$remote_workdir/reports/testnet-e2e-summary.json"
    --force
  )
  if [[ -n "$boundless_requestor_key_file" ]]; then
    remote_args+=(--boundless-requestor-key-file ".ci/secrets/boundless-requestor.key")
  fi
  if [[ "$with_shared_services" == "true" ]]; then
    log "waiting for shared services connectivity from runner"
    wait_for_shared_connectivity_from_runner \
      "$ssh_key_private" \
      "$runner_ssh_user" \
      "$runner_public_ip" \
      "$shared_private_ip" \
      "$shared_postgres_port" \
      "$shared_kafka_port"

    local shared_postgres_dsn shared_kafka_brokers
    log "assembling shared service remote args"
    shared_postgres_dsn="postgres://${shared_postgres_user}:${shared_postgres_password}@${shared_private_ip}:${shared_postgres_port}/${shared_postgres_db}?sslmode=disable"
    shared_kafka_brokers="${shared_private_ip}:${shared_kafka_port}"
    remote_args+=(
      "--shared-postgres-dsn" "$shared_postgres_dsn"
      "--shared-kafka-brokers" "$shared_kafka_brokers"
    )
    log "shared service remote args assembled"
  fi
  remote_args+=("${e2e_args[@]}")

  log "assembling remote e2e arguments"
  local remote_joined_args
  if ! remote_joined_args="$(shell_join "${remote_args[@]}")"; then
    die "failed to build remote command line"
  fi
  [[ -n "$remote_joined_args" ]] || die "remote command line is empty"
  log "remote e2e arguments assembled"

  local remote_run_script
  if ! remote_run_script=$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export PATH="\$HOME/.cargo/bin:\$HOME/.foundry/bin:\$PATH"
export JUNO_FUNDER_PRIVATE_KEY_HEX="\$(tr -d '\r\n' < .ci/secrets/juno-funder.key)"
export JUNO_RPC_USER="\$(tr -d '\r\n' < .ci/secrets/juno-rpc-user.txt)"
export JUNO_RPC_PASS="\$(tr -d '\r\n' < .ci/secrets/juno-rpc-pass.txt)"
if [[ -f .ci/secrets/juno-scan-bearer.txt ]]; then
  export JUNO_SCAN_BEARER_TOKEN="\$(tr -d '\r\n' < .ci/secrets/juno-scan-bearer.txt)"
fi
export AWS_REGION="${aws_region}"
export AWS_DEFAULT_REGION="${aws_region}"
if [[ -n "${AWS_ACCESS_KEY_ID:-}" ]]; then
  export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
fi
if [[ -n "${AWS_SECRET_ACCESS_KEY:-}" ]]; then
  export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
fi
if [[ -n "${AWS_SESSION_TOKEN:-}" ]]; then
  export AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN:-}"
fi
./deploy/operators/dkg/e2e/run-testnet-e2e.sh $remote_joined_args
EOF
); then
    die "failed to render remote run script"
  fi
  log "remote run script ready"

  log "running live e2e on remote host $runner_public_ip"
  local remote_run_status=0
  set +e
  ssh -i "$ssh_key_private" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=6 \
    -o TCPKeepAlive=yes \
    "$runner_ssh_user@$runner_public_ip" \
    "bash -lc $(printf '%q' "$remote_run_script")"
  remote_run_status=$?
  set -e

  log "collecting artifacts"
  scp -r \
    -i "$ssh_key_private" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=6 \
    -o TCPKeepAlive=yes \
    "$runner_ssh_user@$runner_public_ip:$remote_workdir/reports" \
    "$artifacts_dir/" || true

  scp -r \
    -i "$ssh_key_private" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=6 \
    -o TCPKeepAlive=yes \
    "$runner_ssh_user@$runner_public_ip:$remote_workdir/dkg" \
    "$artifacts_dir/" || true

  scp -r \
    -i "$ssh_key_private" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ServerAliveInterval=30 \
    -o ServerAliveCountMax=6 \
    -o TCPKeepAlive=yes \
    "$runner_ssh_user@$runner_public_ip:$remote_workdir/dkg-distributed" \
    "$artifacts_dir/" || true

  local summary_path
  summary_path="$artifacts_dir/reports/testnet-e2e-summary.json"
  if [[ -f "$summary_path" ]]; then
    local juno_tx_hash
    juno_tx_hash="$(
      jq -r '[
        .juno.tx_hash?,
        .bridge.report.juno.proof_of_execution.tx_hash?,
        .bridge.report.juno.tx_hash?,
        .bridge.report.juno.txid?,
        .bridge.report.withdraw.juno_tx_hash?,
        .bridge.report.withdraw.juno_txid?,
        .bridge.report.transactions.juno_withdraw?,
        .bridge.report.transactions.juno_broadcast?,
        .bridge.report.transactions.finalize_withdraw?
      ] | map(select(type == "string" and length > 0)) | .[0] // ""' "$summary_path" 2>/dev/null || true
    )"
    if [[ -n "$juno_tx_hash" ]]; then
      log "juno_tx_hash=$juno_tx_hash"
    else
      log "juno_tx_hash=unavailable"
    fi
    log "summary=$summary_path"
    printf '%s\n' "$summary_path"
  else
    log "summary file not found locally after artifact collection"
  fi

  if (( remote_run_status != 0 )); then
    if [[ "$keep_infra" == "true" ]]; then
      cleanup_enabled="false"
      log "keep-infra enabled after failure; leaving resources up"
    fi
    die "remote live e2e run failed (status=$remote_run_status)"
  fi

  if [[ "$keep_infra" == "true" ]]; then
    cleanup_enabled="false"
    log "keep-infra enabled; leaving resources up"
  fi
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    run) command_run "$@" ;;
    cleanup) command_cleanup "$@" ;;
    -h|--help|"")
      usage
      ;;
    *)
      usage
      die "unsupported command: $cmd"
      ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
