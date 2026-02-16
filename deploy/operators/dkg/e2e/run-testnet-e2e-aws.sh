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
  )

  local remote_script
  remote_script="$(build_remote_prepare_script "$repo_commit")"

  ssh "${ssh_opts[@]}" "$ssh_user@$ssh_host" "bash -lc $(printf '%q' "$remote_script")"
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
  local patched_build_rs

  install_dir="\$(ls -dt /tmp/cargo-install* 2>/dev/null | head -n1 || true)"
  if [[ -z "\$install_dir" ]]; then
    echo "boundless diagnostics: no /tmp/cargo-install* directory found"
    return 0
  fi

  generated_file="\$(find "\$install_dir" -type f -name 'boundless_market_generated.rs' | head -n1 || true)"
  if [[ -n "\$generated_file" && -f "\$generated_file" ]]; then
    echo "boundless diagnostics: generated file: \$generated_file"
    if command -v rg >/dev/null 2>&1; then
      rg -n "__BOUNDLESS_DUMMY__|alloy::sol!|enum|library|interface" "\$generated_file" | tail -n 40 || true
    fi
    echo "boundless diagnostics: generated file tail"
    tail -n 80 "\$generated_file" || true
  else
    echo "boundless diagnostics: generated file not found under \$install_dir"
  fi

  patched_build_rs="\$HOME/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/boundless-market-0.14.1/build.rs"
  if [[ -f "\$patched_build_rs" ]]; then
    echo "boundless diagnostics: patched build.rs snippet (\$patched_build_rs)"
    sed -n '116,130p' "\$patched_build_rs" || true
  fi
}

run_with_retry() {
  local attempt
  for attempt in \$(seq 1 3); do
    if "\$@"; then
      return 0
    fi
    if [[ "\$*" == "cargo install --locked boundless-cli --version 0.14.1" ]]; then
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

prepare_boundless_market_patch() {
  local cargo_registry_src
  local cargo_index_dir
  local crate_dir
  local build_rs
  local crate_url
  local crate_archive
  local candidate_dir
  local candidate_build_rs

  patch_build_rs() {
    local target_build_rs="\$1"

    if [[ ! -f "\$target_build_rs" ]]; then
      echo "boundless-market source missing: \$target_build_rs" >&2
      return 1
    fi

    if ! grep -q "__BOUNDLESS_DUMMY__" "\$target_build_rs"; then
      perl -0pi -e 's/\\{combined_sol_contents\\}/\\{combined_sol_contents\\}\\n            enum __BOUNDLESS_DUMMY__ {{ __BOUNDLESS_DUMMY_VALUE__ }}/s' "\$target_build_rs"
    fi

    if ! grep -q "__BOUNDLESS_DUMMY__" "\$target_build_rs"; then
      echo "boundless-market patch marker missing after patch attempt: \$target_build_rs" >&2
      return 1
    fi

    echo "boundless-market build.rs patched: \$target_build_rs"
  }

  cargo_registry_src="\$HOME/.cargo/registry/src"
  mkdir -p "\$cargo_registry_src"

  cargo_index_dir="\$cargo_registry_src/index.crates.io-1949cf8c6b5b557f"
  mkdir -p "\$cargo_index_dir"

  crate_dir="\$cargo_index_dir/boundless-market-0.14.1"
  build_rs="\$crate_dir/build.rs"
  if [[ ! -f "\$build_rs" ]]; then
    crate_url="https://static.crates.io/crates/boundless-market/boundless-market-0.14.1.crate"
    crate_archive="/tmp/boundless-market-0.14.1.crate"
    rm -rf "\$crate_dir"
    curl -fsSL "\$crate_url" -o "\$crate_archive"
    tar -xzf "\$crate_archive" -C "\$cargo_index_dir"
  fi

  patch_build_rs "\$build_rs"

  for candidate_dir in "\$cargo_registry_src"/index.crates.io-*; do
    [[ -d "\$candidate_dir" ]] || continue
    candidate_build_rs="\$candidate_dir/boundless-market-0.14.1/build.rs"
    if [[ "\$candidate_build_rs" != "\$build_rs" && -f "\$candidate_build_rs" ]]; then
      patch_build_rs "\$candidate_build_rs"
    fi
  done
}

prepare_boundless_market_patch
run_with_retry cargo install --locked boundless-cli --version 0.14.1
run_with_retry cargo install --locked cargo-risczero --version 3.0.5

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

  local tfvars_file state_file
  tfvars_file="$infra_dir/terraform.tfvars.json"
  state_file="$infra_dir/terraform.tfstate"

  jq -n \
    --arg aws_region "$aws_region" \
    --arg deployment_id "$deployment_id" \
    --arg name_prefix "$aws_name_prefix" \
    --arg instance_type "$aws_instance_type" \
    --argjson root_volume_size_gb "$aws_root_volume_gb" \
    --arg allowed_ssh_cidr "$ssh_allowed_cidr" \
    --arg ssh_public_key "$(cat "$ssh_key_public")" \
    '{
      aws_region: $aws_region,
      deployment_id: $deployment_id,
      name_prefix: $name_prefix,
      instance_type: $instance_type,
      root_volume_size_gb: $root_volume_size_gb,
      allowed_ssh_cidr: $allowed_ssh_cidr,
      ssh_public_key: $ssh_public_key
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
  remote_args+=("${e2e_args[@]}")

  local remote_joined_args
  remote_joined_args="$(shell_join "${remote_args[@]}")"

  local remote_run_script
  remote_run_script=$(cat <<EOF
set -euo pipefail
cd "$remote_repo"
export PATH="\$HOME/.cargo/bin:\$HOME/.foundry/bin:\$PATH"
export JUNO_FUNDER_PRIVATE_KEY_HEX="\$(tr -d '\r\n' < .ci/secrets/juno-funder.key)"
./deploy/operators/dkg/e2e/run-testnet-e2e.sh $remote_joined_args
EOF
)

  log "running live e2e on remote host $runner_public_ip"
  ssh -i "$ssh_key_private" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$runner_ssh_user@$runner_public_ip" \
    "bash -lc $(printf '%q' "$remote_run_script")"

  log "collecting artifacts"
  scp -r \
    -i "$ssh_key_private" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    "$runner_ssh_user@$runner_public_ip:$remote_workdir/reports" \
    "$artifacts_dir/" || true

  scp -r \
    -i "$ssh_key_private" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
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
