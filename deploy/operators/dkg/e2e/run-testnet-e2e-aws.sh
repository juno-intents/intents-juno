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
  --aws-root-volume-gb <n>             root volume size (default: 200)
  --ssh-allowed-cidr <cidr>            inbound SSH CIDR (default: caller public IP /32)
  --base-funder-key-file <path>        file with Base funder private key hex (required)
  --juno-funder-key-file <path>        file with Juno funder private key hex (required)
  --boundless-requestor-key-file <p>   optional file with Boundless requestor private key hex
  --without-shared-services            skip provisioning shared Postgres/Kafka host
  --shared-postgres-user <user>        shared Postgres username (default: postgres)
  --shared-postgres-db <name>          shared Postgres DB name (default: intents_e2e)
  --shared-postgres-port <port>        shared Postgres TCP port (default: 5432)
  --shared-kafka-port <port>           shared Kafka TCP port (default: 9092)
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

remote_prepare_shared_host() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local shared_private_ip="$4"
  local shared_postgres_user="$5"
  local shared_postgres_password="$6"
  local shared_postgres_db="$7"
  local shared_postgres_port="$8"
  local shared_kafka_port="$9"

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
    build_remote_shared_prepare_script \
      "$shared_private_ip" \
      "$shared_postgres_user" \
      "$shared_postgres_password" \
      "$shared_postgres_db" \
      "$shared_postgres_port" \
      "$shared_kafka_port"
  )"

  local attempt
  local prep_log
  local ssh_status
  for attempt in $(seq 1 3); do
    log "preparing shared services host (attempt $attempt/3)"
    prep_log="$(mktemp)"
    set +e
    ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" "bash -lc $(printf '%q' "$remote_script")" 2>&1 | tee "$prep_log"
    ssh_status="${PIPESTATUS[0]}"
    set -e

    if (( ssh_status == 0 )); then
      rm -f "$prep_log"
      return 0
    fi
    if grep -q "shared services ready on host" "$prep_log"; then
      log "shared services reported ready despite ssh exit status=$ssh_status; continuing"
      rm -f "$prep_log"
      return 0
    fi
    rm -f "$prep_log"
    if [[ $attempt -lt 3 ]]; then
      sleep 5
    fi
  done

  return 1
}

wait_for_shared_connectivity_from_runner() {
  local ssh_private_key="$1"
  local ssh_user="$2"
  local ssh_host="$3"
  local shared_private_ip="$4"
  local shared_postgres_port="$5"
  local shared_kafka_port="$6"

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
      "$shared_private_ip" \
      "$shared_postgres_port" \
      "$shared_kafka_port"
  )"

  local attempt
  local probe_log
  local ssh_status
  for attempt in $(seq 1 3); do
    log "checking shared services connectivity from runner (attempt $attempt/3)"
    probe_log="$(mktemp)"
    set +e
    ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" "bash -lc $(printf '%q' "$remote_script")" 2>&1 | tee "$probe_log"
    ssh_status="${PIPESTATUS[0]}"
    set -e

    if (( ssh_status == 0 )); then
      rm -f "$probe_log"
      return 0
    fi
    if grep -q "shared services reachable from runner" "$probe_log"; then
      log "shared connectivity reported ready despite ssh exit status=$ssh_status; continuing"
      rm -f "$probe_log"
      return 0
    fi
    rm -f "$probe_log"
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
    if [[ "\$*" == cargo\ install\ --path* ]]; then
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

export PATH="\$HOME/.cargo/bin:\$HOME/.foundry/bin:\$PATH"
if ! command -v foundryup >/dev/null 2>&1; then
  curl -L https://foundry.paradigm.xyz | bash
fi
foundryup

# Keep this pinned to the release branch documented for mainnet requestors.
run_with_retry rustup toolchain install 1.91.1 --profile minimal
run_with_retry rustup default 1.91.1
rustc --version
BOUNDLESS_CLI_SOURCE_DIR="/tmp/boundless-cli-release-1.2"
if [[ -d "\$BOUNDLESS_CLI_SOURCE_DIR/.git" ]]; then
  git -C "\$BOUNDLESS_CLI_SOURCE_DIR" fetch --depth 1 origin release-1.2
  git -C "\$BOUNDLESS_CLI_SOURCE_DIR" checkout --force FETCH_HEAD
else
  git clone --depth 1 --branch release-1.2 https://github.com/boundless-xyz/boundless "\$BOUNDLESS_CLI_SOURCE_DIR"
fi

boundless_market_build_rs="\$BOUNDLESS_CLI_SOURCE_DIR/crates/boundless-market/build.rs"
if [[ ! -f "\$boundless_market_build_rs" ]]; then
  echo "boundless-market build script missing: \$boundless_market_build_rs" >&2
  exit 1
fi

# Work around alloy::sol parser edge case during cargo-install codegen on Linux.
if ! grep -q "__BOUNDLESS_DUMMY__" "\$boundless_market_build_rs"; then
  perl -0pi -e 's/\\{combined_sol_contents\\}/\\{combined_sol_contents\\}\\n            enum __BOUNDLESS_DUMMY__ {{ __BOUNDLESS_DUMMY_VALUE__ }}/s' "\$boundless_market_build_rs"
fi
if ! grep -q "__BOUNDLESS_DUMMY__" "\$boundless_market_build_rs"; then
  echo "failed to patch boundless market build script: \$boundless_market_build_rs" >&2
  exit 1
fi

boundless_cli_target_version="1.2.0"
boundless_cli_target_branch="release-1.2"
boundless_version_output=""
if command -v boundless >/dev/null 2>&1; then
  boundless_version_output="\$(boundless --version 2>/dev/null || true)"
fi
if [[ "\$boundless_version_output" == *"boundless-cli \$boundless_cli_target_version"* && "\$boundless_version_output" == *"branch:\$boundless_cli_target_branch"* ]]; then
  echo "boundless-cli already installed at target version; skipping reinstall"
else
  run_with_retry cargo +1.91.1 install --path "\$BOUNDLESS_CLI_SOURCE_DIR/crates/boundless-cli" --locked --force
fi
boundless --version

cargo_risczero_target_version="3.0.5"
cargo_risczero_version_output=""
if command -v cargo-risczero >/dev/null 2>&1; then
  cargo_risczero_version_output="\$(cargo-risczero --version 2>/dev/null || true)"
fi
if [[ "\$cargo_risczero_version_output" == *"\$cargo_risczero_target_version"* ]]; then
  echo "cargo-risczero already installed at target version; skipping reinstall"
else
  run_with_retry cargo +1.91.1 install --locked cargo-risczero --version 3.0.5
fi

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

build_remote_shared_prepare_script() {
  local shared_private_ip="$1"
  local shared_postgres_user="$2"
  local shared_postgres_password="$3"
  local shared_postgres_db="$4"
  local shared_postgres_port="$5"
  local shared_kafka_port="$6"

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

docker_pull_with_retry() {
  local image="\$1"
  local attempt
  for attempt in \$(seq 1 12); do
    if sudo docker pull "\$image"; then
      return 0
    fi
    if [[ \$attempt -lt 12 ]]; then
      sleep 5
    fi
  done
  return 1
}

run_apt_with_retry update -y
run_apt_with_retry install -y ca-certificates curl docker.io netcat-openbsd postgresql-client
sudo systemctl enable --now docker

docker_pull_with_retry postgres:16-alpine
docker_pull_with_retry docker.redpanda.com/redpandadata/redpanda:v24.3.7

sudo docker rm -f intents-shared-postgres intents-shared-kafka >/dev/null 2>&1 || true

sudo docker run -d \
  --name intents-shared-postgres \
  --restart unless-stopped \
  -e POSTGRES_USER='${shared_postgres_user}' \
  -e POSTGRES_PASSWORD='${shared_postgres_password}' \
  -e POSTGRES_DB='${shared_postgres_db}' \
  -p ${shared_postgres_port}:5432 \
  postgres:16-alpine

sudo docker run -d \
  --name intents-shared-kafka \
  --restart unless-stopped \
  -p ${shared_kafka_port}:9092 \
  docker.redpanda.com/redpandadata/redpanda:v24.3.7 \
  redpanda start \
    --overprovisioned \
    --smp 1 \
    --memory 1G \
    --reserve-memory 0M \
    --node-id 0 \
    --check=false \
    --kafka-addr PLAINTEXT://0.0.0.0:9092 \
    --advertise-kafka-addr PLAINTEXT://${shared_private_ip}:${shared_kafka_port}

for attempt in \$(seq 1 90); do
  if sudo docker exec intents-shared-postgres pg_isready -h 127.0.0.1 -p 5432 -U '${shared_postgres_user}' -d '${shared_postgres_db}' >/dev/null 2>&1 \
    && timeout 2 bash -lc '</dev/tcp/127.0.0.1/${shared_kafka_port}' >/dev/null 2>&1; then
    echo "shared services ready on host"
    exit 0
  fi
  if [[ \$attempt -lt 90 ]]; then
    sleep 2
  fi
done

echo "shared service readiness failed; docker status follows:" >&2
sudo docker ps -a >&2 || true
sudo docker logs --tail 80 intents-shared-postgres >&2 || true
sudo docker logs --tail 80 intents-shared-kafka >&2 || true
exit 1
EOF
}

build_runner_shared_probe_script() {
  local shared_private_ip="$1"
  local shared_postgres_port="$2"
  local shared_kafka_port="$3"

  cat <<EOF
set -euo pipefail
for attempt in \$(seq 1 90); do
  if timeout 2 bash -lc '</dev/tcp/${shared_private_ip}/${shared_postgres_port}' >/dev/null 2>&1 \
    && timeout 2 bash -lc '</dev/tcp/${shared_private_ip}/${shared_kafka_port}' >/dev/null 2>&1; then
    echo "shared services reachable from runner"
    exit 0
  fi
  if [[ \$attempt -lt 90 ]]; then
    sleep 2
  fi
done

echo "timed out waiting for shared services connectivity from runner to ${shared_private_ip}" >&2
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
  local aws_root_volume_gb="200"
  local ssh_allowed_cidr=""
  local base_funder_key_file=""
  local juno_funder_key_file=""
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
      --aws-root-volume-gb)
        [[ $# -ge 2 ]] || die "missing value for --aws-root-volume-gb"
        aws_root_volume_gb="$2"
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
  [[ -f "$base_funder_key_file" ]] || die "base funder key file not found: $base_funder_key_file"
  [[ -f "$juno_funder_key_file" ]] || die "juno funder key file not found: $juno_funder_key_file"
  [[ "$shared_postgres_port" =~ ^[0-9]+$ ]] || die "--shared-postgres-port must be numeric"
  [[ "$shared_kafka_port" =~ ^[0-9]+$ ]] || die "--shared-kafka-port must be numeric"
  [[ -n "$shared_postgres_user" ]] || die "--shared-postgres-user must not be empty"
  [[ -n "$shared_postgres_db" ]] || die "--shared-postgres-db must not be empty"
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
    --argjson root_volume_size_gb "$aws_root_volume_gb" \
    --arg allowed_ssh_cidr "$ssh_allowed_cidr" \
    --arg ssh_public_key "$(cat "$ssh_key_public")" \
    --argjson provision_shared_services "$provision_shared_services_json" \
    --arg shared_postgres_user "$shared_postgres_user" \
    --arg shared_postgres_password "$shared_postgres_password" \
    --arg shared_postgres_db "$shared_postgres_db" \
    --argjson shared_postgres_port "$shared_postgres_port" \
    --argjson shared_kafka_port "$shared_kafka_port" \
    '{
      aws_region: $aws_region,
      deployment_id: $deployment_id,
      name_prefix: $name_prefix,
      instance_type: $instance_type,
      root_volume_size_gb: $root_volume_size_gb,
      allowed_ssh_cidr: $allowed_ssh_cidr,
      ssh_public_key: $ssh_public_key,
      provision_shared_services: $provision_shared_services,
      shared_postgres_user: $shared_postgres_user,
      shared_postgres_password: $shared_postgres_password,
      shared_postgres_db: $shared_postgres_db,
      shared_postgres_port: $shared_postgres_port,
      shared_kafka_port: $shared_kafka_port
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

  local summary_path
  summary_path="$artifacts_dir/reports/testnet-e2e-summary.json"
  if [[ -f "$summary_path" ]]; then
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
