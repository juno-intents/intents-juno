#!/usr/bin/env bash
# shellcheck shell=bash
#
# Full-lifecycle local e2e runner.
#
# Provisions AWS infrastructure via Terraform, prepares operators, runs the
# distributed DKG ceremony, executes the e2e test on a remote runner host,
# and tears everything down on exit.
#
# Usage:
#   ./run-e2e-local.sh run   [options]   # Full lifecycle
#   ./run-e2e-local.sh resume [options]   # Resume from existing infra
#   ./run-e2e-local.sh cleanup [options]  # Tear down leftover infra
#
# Auto-discovers:
#   - Base funder key:     $REPO_ROOT/tmp/funders/base-funder.key
#   - Juno funder seed:    $REPO_ROOT/tmp/funders-orchard/juno-funder.seed.txt
#   - SP1 requestor key:   ~/.juno-secrets/boundless-requestor-mainnet.key
#   - Operator AMI:        from GH release operator-stack-ami-latest
#   - SP1 vkeys + ELFs:    from GH release bridge-guests-latest
#   - Proof services image: from GH release shared-proof-services-image-latest

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"
prepare_script_runtime "$SCRIPT_DIR"

# ── Defaults ─────────────────────────────────────────────────────────────────

AWS_PROFILE="${AWS_PROFILE:-juno}"
AWS_REGION="${AWS_REGION:-us-east-1}"
WORKDIR=""
TERRAFORM_DIR="$REPO_ROOT/deploy/shared/terraform/live-e2e"
OPERATOR_COUNT=5
OPERATOR_THRESHOLD=3
OPERATOR_BASE_PORT=18443
OPERATOR_AMI_ID=""
RUNNER_INSTANCE_TYPE="c7i.2xlarge"
OPERATOR_INSTANCE_TYPE="c7i.large"
BRIDGE_VERIFIER_ADDRESS="0x397A5f7f3dBd538f23DE225B51f532c34448dA9B"
BRIDGE_GUEST_RELEASE_TAG="bridge-guests-latest"
PROOF_SERVICES_RELEASE_TAG="shared-proof-services-image-latest"
DKG_RELEASE_TAG="v0.1.0"
BASE_RPC_URL="https://sepolia.base.org"
BASE_CHAIN_ID="84532"
KEEP_INFRA=false
COMMAND=""

# Auto-discovered paths
BASE_FUNDER_KEY_FILE=""
JUNO_FUNDER_KEY_FILE=""
JUNO_FUNDER_SEED_FILE=""
JUNO_FUNDER_SOURCE_ADDRESS_FILE=""
SP1_REQUESTOR_KEY_FILE=""

# Resolved from GH releases
BRIDGE_DEPOSIT_IMAGE_ID=""
BRIDGE_WITHDRAW_IMAGE_ID=""
SP1_DEPOSIT_PROGRAM_URL=""
SP1_WITHDRAW_PROGRAM_URL=""
PROOF_SERVICES_IMAGE=""

# Terraform outputs (populated after apply)
RUNNER_PUBLIC_IP=""
RUNNER_SSH_USER="ubuntu"
SHARED_POSTGRES_ENDPOINT=""
SHARED_POSTGRES_DSN=""
SHARED_KAFKA_BROKERS=""
SHARED_IPFS_API_URL=""
SHARED_ECS_CLUSTER_ARN=""
SHARED_PROOF_REQUESTOR_SERVICE=""
SHARED_PROOF_FUNDER_SERVICE=""
DKG_KMS_KEY_ARN=""
DKG_S3_BUCKET=""
DKG_S3_KEY_PREFIX=""
declare -a OPERATOR_PUBLIC_IPS=()
declare -a OPERATOR_PRIVATE_IPS=()

# Derived owallet keys (from DKG UFVK)
SP1_DEPOSIT_OWALLET_IVK_HEX=""
SP1_WITHDRAW_OWALLET_OVK_HEX=""

# Backoffice
BACKOFFICE_PORT=8082
BACKOFFICE_AUTH_TOKEN=""
BACKOFFICE_SG_RULE_ADDED=false

# Cleanup globals
CLEANUP_ENABLED=false
CLEANUP_SP1_SECRET_ARN=""

# SSH
SSH_KEY_PRIVATE=""
SSH_KEY_PUBLIC=""
SSH_OPTS=()

# ── Colours ──────────────────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)] ✓${NC} $*" >&2; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] !${NC} $*" >&2; }
step() { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}" >&2; }

# ── Checkpoint helpers ───────────────────────────────────────────────────────

CHECKPOINT_DIR=""

checkpoint_done() { [[ -f "$CHECKPOINT_DIR/$1.done" ]]; }

checkpoint_mark() {
  mkdir -p "$CHECKPOINT_DIR"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$CHECKPOINT_DIR/$1.done"
  ok "Checkpoint '$1' completed"
}

# ── Usage ────────────────────────────────────────────────────────────────────

usage() {
  cat <<'EOF'
Usage:
  run-e2e-local.sh run     [options]   Full lifecycle: provision → test → teardown
  run-e2e-local.sh resume  [options]   Resume using existing infra + DKG state
  run-e2e-local.sh cleanup [options]   Destroy leftover infrastructure

Options:
  --workdir <path>             Working directory (default: $REPO_ROOT/tmp/e2e-local)
  --aws-region <region>        AWS region (default: us-east-1)
  --aws-profile <name>         AWS CLI profile (default: juno)
  --operator-count <n>         Number of operator hosts (default: 5)
  --operator-threshold <n>     Signature threshold (default: 3)
  --operator-ami-id <ami-id>   Override operator AMI (default: auto-resolve from GH)
  --base-rpc-url <url>         Base testnet RPC (default: https://sepolia.base.org)
  --keep-infra                 Do not destroy infra on exit
  --base-funder-key-file <p>   Override Base funder key file
  --sp1-requestor-key-file <p> Override SP1 requestor key file

Auto-discovered secrets (override with flags if needed):
  Base funder key:       tmp/funders/base-funder.key
  Juno funder seed:      tmp/funders-orchard/juno-funder.seed.txt
  SP1 requestor key:     ~/.juno-secrets/boundless-requestor-mainnet.key
  Operator AMI:          from GH release operator-stack-ami-latest
  SP1 guest programs:    from GH release bridge-guests-latest
  Proof services image:  from GH release shared-proof-services-image-latest
EOF
  exit 1
}

# ── Argument parsing ─────────────────────────────────────────────────────────

parse_args() {
  [[ $# -gt 0 ]] || usage
  COMMAND="$1"; shift

  case "$COMMAND" in
    run|resume|cleanup) ;;
    -h|--help) usage ;;
    *) die "unknown command: $COMMAND (expected: run, resume, cleanup)" ;;
  esac

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)                WORKDIR="$2"; shift 2 ;;
      --aws-region)             AWS_REGION="$2"; shift 2 ;;
      --aws-profile)            AWS_PROFILE="$2"; shift 2 ;;
      --operator-count)         OPERATOR_COUNT="$2"; shift 2 ;;
      --operator-threshold)     OPERATOR_THRESHOLD="$2"; shift 2 ;;
      --operator-ami-id)        OPERATOR_AMI_ID="$2"; shift 2 ;;
      --base-rpc-url)           BASE_RPC_URL="$2"; shift 2 ;;
      --base-funder-key-file)   BASE_FUNDER_KEY_FILE="$2"; shift 2 ;;
      --sp1-requestor-key-file) SP1_REQUESTOR_KEY_FILE="$2"; shift 2 ;;
      --keep-infra)             KEEP_INFRA=true; shift ;;
      -h|--help) usage ;;
      *) die "unknown option: $1" ;;
    esac
  done

  WORKDIR="${WORKDIR:-$REPO_ROOT/tmp/e2e-local}"
  CHECKPOINT_DIR="$WORKDIR/.checkpoints"
}

# ── Auto-discovery ───────────────────────────────────────────────────────────

auto_discover_secrets() {
  step "Auto-discovering secrets"

  # Base funder key
  if [[ -z "$BASE_FUNDER_KEY_FILE" ]]; then
    local candidates=(
      "$REPO_ROOT/tmp/funders/base-funder.key"
      "$REPO_ROOT/tmp/funders-orchard/base-funder.key"
    )
    for f in "${candidates[@]}"; do
      if [[ -f "$f" ]]; then
        BASE_FUNDER_KEY_FILE="$f"
        break
      fi
    done
  fi
  [[ -n "$BASE_FUNDER_KEY_FILE" && -f "$BASE_FUNDER_KEY_FILE" ]] || \
    die "base funder key not found; provide --base-funder-key-file or place at tmp/funders/base-funder.key"
  ok "Base funder key: $BASE_FUNDER_KEY_FILE"

  # Juno funder (prefer orchard wallet with seed phrase)
  if [[ -z "$JUNO_FUNDER_SEED_FILE" ]]; then
    local seed_file="$REPO_ROOT/tmp/funders-orchard/juno-funder.seed.txt"
    if [[ -f "$seed_file" ]]; then
      JUNO_FUNDER_SEED_FILE="$seed_file"
    fi
  fi
  if [[ -z "$JUNO_FUNDER_KEY_FILE" && -z "$JUNO_FUNDER_SEED_FILE" ]]; then
    local key_file="$REPO_ROOT/tmp/funders/juno-funder.key"
    if [[ -f "$key_file" ]]; then
      JUNO_FUNDER_KEY_FILE="$key_file"
    fi
  fi
  if [[ -n "$JUNO_FUNDER_SEED_FILE" ]]; then
    ok "Juno funder seed: $JUNO_FUNDER_SEED_FILE"
  elif [[ -n "$JUNO_FUNDER_KEY_FILE" ]]; then
    ok "Juno funder key: $JUNO_FUNDER_KEY_FILE"
  else
    warn "no Juno funder key/seed found; witness metadata may fail"
  fi

  # Juno funder source address
  local ua_file="$REPO_ROOT/tmp/funders/juno-funder.ua"
  if [[ -f "$ua_file" ]]; then
    JUNO_FUNDER_SOURCE_ADDRESS_FILE="$ua_file"
    ok "Juno funder source address: $ua_file"
  fi

  # SP1 requestor key
  if [[ -z "$SP1_REQUESTOR_KEY_FILE" ]]; then
    local sp1_candidates=(
      "$HOME/.juno-secrets/boundless-requestor-mainnet.key"
      "$REPO_ROOT/tmp/funders/boundless-requestor-mainnet.key"
    )
    for f in "${sp1_candidates[@]}"; do
      if [[ -f "$f" ]]; then
        SP1_REQUESTOR_KEY_FILE="$f"
        break
      fi
    done
  fi
  [[ -n "$SP1_REQUESTOR_KEY_FILE" && -f "$SP1_REQUESTOR_KEY_FILE" ]] || \
    die "SP1 requestor key not found; provide --sp1-requestor-key-file or place at ~/.juno-secrets/boundless-requestor-mainnet.key"
  ok "SP1 requestor key: $SP1_REQUESTOR_KEY_FILE"
}

# ── GH release resolution ───────────────────────────────────────────────────

resolve_gh_releases() {
  step "Resolving GitHub release assets"

  # Bridge guest programs (vkeys + ELF URLs)
  log "downloading bridge-guest-release.env from $BRIDGE_GUEST_RELEASE_TAG..."
  local guest_env
  guest_env="$(gh release download "$BRIDGE_GUEST_RELEASE_TAG" --pattern "bridge-guest-release.env" --output - 2>/dev/null)" || \
    die "failed to download bridge-guest-release.env from release $BRIDGE_GUEST_RELEASE_TAG"

  BRIDGE_DEPOSIT_IMAGE_ID="$(grep '^BRIDGE_DEPOSIT_IMAGE_ID=' <<<"$guest_env" | cut -d= -f2)"
  BRIDGE_WITHDRAW_IMAGE_ID="$(grep '^BRIDGE_WITHDRAW_IMAGE_ID=' <<<"$guest_env" | cut -d= -f2)"
  SP1_DEPOSIT_PROGRAM_URL="$(grep '^SP1_DEPOSIT_PROGRAM_URL=' <<<"$guest_env" | cut -d= -f2)"
  SP1_WITHDRAW_PROGRAM_URL="$(grep '^SP1_WITHDRAW_PROGRAM_URL=' <<<"$guest_env" | cut -d= -f2)"

  [[ -n "$BRIDGE_DEPOSIT_IMAGE_ID" ]] || die "missing BRIDGE_DEPOSIT_IMAGE_ID in release"
  [[ -n "$BRIDGE_WITHDRAW_IMAGE_ID" ]] || die "missing BRIDGE_WITHDRAW_IMAGE_ID in release"
  ok "deposit vkey: $BRIDGE_DEPOSIT_IMAGE_ID"
  ok "withdraw vkey: $BRIDGE_WITHDRAW_IMAGE_ID"

  # Operator AMI (if not overridden)
  if [[ -z "$OPERATOR_AMI_ID" ]]; then
    log "resolving operator AMI from GH release operator-stack-ami-latest..."
    local ami_body
    ami_body="$(gh release view operator-stack-ami-latest --json body --jq '.body' 2>/dev/null)" || \
      die "failed to read operator-stack-ami-latest release"
    OPERATOR_AMI_ID="$(echo "$ami_body" | sed -n 's/.*AMI:[[:space:]]*\(ami-[a-z0-9]*\).*/\1/p' | head -1)"
    [[ -n "$OPERATOR_AMI_ID" ]] || die "could not extract AMI ID from operator-stack-ami-latest release"
  fi
  ok "Operator AMI: $OPERATOR_AMI_ID"

  # Shared proof services image
  log "resolving proof services image from $PROOF_SERVICES_RELEASE_TAG..."
  local manifest
  manifest="$(gh release download "$PROOF_SERVICES_RELEASE_TAG" \
    --pattern "shared-proof-services-image-manifest.json" --output - 2>/dev/null)" || \
    die "failed to download proof services manifest from $PROOF_SERVICES_RELEASE_TAG"
  PROOF_SERVICES_IMAGE="$(jq -r ".regions.\"$AWS_REGION\".image_uri // empty" <<<"$manifest")"
  if [[ -z "$PROOF_SERVICES_IMAGE" ]]; then
    PROOF_SERVICES_IMAGE="$(jq -r '.image_uri // empty' <<<"$manifest")"
  fi
  [[ -n "$PROOF_SERVICES_IMAGE" ]] || die "could not resolve proof services image for region $AWS_REGION"
  ok "Proof services image: $PROOF_SERVICES_IMAGE"
}

# ── SSH key management ───────────────────────────────────────────────────────

setup_ssh_keys() {
  local ssh_dir="$WORKDIR/ssh"
  mkdir -p "$ssh_dir"

  SSH_KEY_PRIVATE="$ssh_dir/id_ed25519"
  SSH_KEY_PUBLIC="$ssh_dir/id_ed25519.pub"

  if [[ -s "$SSH_KEY_PRIVATE" && -s "$SSH_KEY_PUBLIC" ]]; then
    log "reusing existing SSH keypair from prior run"
  else
    rm -f "$SSH_KEY_PRIVATE" "$SSH_KEY_PUBLIC"
    ssh-keygen -t ed25519 -N "" -f "$SSH_KEY_PRIVATE" >/dev/null
    ok "generated SSH keypair"
  fi

  SSH_OPTS=(
    -i "$SSH_KEY_PRIVATE"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o ConnectTimeout=10
    -o LogLevel=ERROR
  )
}

# ── Terraform lifecycle ──────────────────────────────────────────────────────

generate_tfvars() {
  local tfvars_file="$1"
  local deployment_id="$2"
  local ssh_allowed_cidr="$3"
  local shared_postgres_password="$4"
  local sp1_secret_arn="${5:-}"

  jq -n \
    --arg aws_region "$AWS_REGION" \
    --arg deployment_id "$deployment_id" \
    --arg name_prefix "juno-e2e-local" \
    --arg instance_type "$RUNNER_INSTANCE_TYPE" \
    --arg runner_ami_id "" \
    --argjson root_volume_size_gb 60 \
    --argjson operator_instance_count "$OPERATOR_COUNT" \
    --arg operator_instance_type "$OPERATOR_INSTANCE_TYPE" \
    --arg operator_ami_id "$OPERATOR_AMI_ID" \
    --argjson operator_root_volume_size_gb 40 \
    --arg shared_ami_id "" \
    --argjson operator_base_port "$OPERATOR_BASE_PORT" \
    --arg allowed_ssh_cidr "$ssh_allowed_cidr" \
    --arg ssh_public_key "$(cat "$SSH_KEY_PUBLIC")" \
    --argjson provision_shared_services true \
    --arg shared_postgres_user "postgres" \
    --arg shared_postgres_password "$shared_postgres_password" \
    --arg shared_postgres_db "intents_e2e" \
    --arg shared_proof_service_image "$PROOF_SERVICES_IMAGE" \
    --arg shared_sp1_requestor_secret_arn "$sp1_secret_arn" \
    --argjson shared_postgres_port 5432 \
    --argjson shared_kafka_port 9094 \
    --argjson runner_associate_public_ip_address true \
    --argjson operator_associate_public_ip_address true \
    --argjson shared_ecs_assign_public_ip false \
    --arg dkg_s3_key_prefix "dkg/keypackages" \
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
      shared_postgres_user: "postgres",
      shared_postgres_password: $shared_postgres_password,
      shared_postgres_db: "intents_e2e",
      shared_proof_service_image: $shared_proof_service_image,
      shared_sp1_requestor_secret_arn: $shared_sp1_requestor_secret_arn,
      shared_postgres_port: $shared_postgres_port,
      shared_kafka_port: $shared_kafka_port,
      runner_associate_public_ip_address: $runner_associate_public_ip_address,
      operator_associate_public_ip_address: $operator_associate_public_ip_address,
      shared_ecs_assign_public_ip: $shared_ecs_assign_public_ip,
      dkg_s3_key_prefix: $dkg_s3_key_prefix
    }' > "$tfvars_file"
}

tf_cmd() {
  env AWS_PROFILE="$AWS_PROFILE" AWS_REGION="$AWS_REGION" \
    TF_IN_AUTOMATION=1 terraform "$@"
}

terraform_apply() {
  step "Terraform apply"

  local infra_dir="$WORKDIR/infra"
  local state_file="$infra_dir/terraform.tfstate"
  local tfvars_file="$infra_dir/terraform.tfvars.json"
  mkdir -p "$infra_dir"

  # Detect caller public IP for SSH ingress
  local my_ip
  my_ip="$(curl -sf https://checkip.amazonaws.com | tr -d '\r\n')" || \
    die "failed to detect public IP for SSH ingress CIDR"
  local ssh_cidr="${my_ip}/32"
  ok "SSH ingress CIDR: $ssh_cidr"

  # Generate a stable deployment ID from the workdir name
  local deployment_id
  deployment_id="$(basename "$WORKDIR" | tr -cs '[:alnum:]' '-' | tr '[:upper:]' '[:lower:]')"
  deployment_id="${deployment_id#-}"   # strip leading hyphen
  deployment_id="${deployment_id%-}"   # strip trailing hyphen
  deployment_id="${deployment_id:0:20}"

  # Generate Postgres password (or reuse from prior run)
  local pg_pass_file="$WORKDIR/local-secrets/postgres-password.txt"
  mkdir -p "$WORKDIR/local-secrets"
  local pg_password
  if [[ -f "$pg_pass_file" ]]; then
    pg_password="$(cat "$pg_pass_file")"
  else
    pg_password="$(openssl rand -hex 16)"
    echo -n "$pg_password" > "$pg_pass_file"
    chmod 600 "$pg_pass_file"
  fi

  # Create SP1 Secrets Manager secret (for proof-requestor/proof-funder ECS tasks)
  local sp1_secret_arn=""
  local sp1_secret_arn_file="$WORKDIR/local-secrets/sp1-secret-arn.txt"
  if [[ -f "$sp1_secret_arn_file" ]]; then
    sp1_secret_arn="$(cat "$sp1_secret_arn_file")"
    log "reusing SP1 Secrets Manager secret: $sp1_secret_arn"
  else
    local sp1_key_hex
    sp1_key_hex="$(tr -d '\r\n' < "$SP1_REQUESTOR_KEY_FILE")"
    local secret_name="juno-e2e-local-${deployment_id}-sp1-requestor"
    log "creating SP1 Secrets Manager secret: $secret_name"
    sp1_secret_arn="$(
      env AWS_PROFILE="$AWS_PROFILE" aws secretsmanager create-secret \
        --region "$AWS_REGION" \
        --name "$secret_name" \
        --secret-string "$sp1_key_hex" \
        --query 'ARN' --output text 2>/dev/null
    )" || die "failed to create SP1 secret in Secrets Manager"
    echo -n "$sp1_secret_arn" > "$sp1_secret_arn_file"
    CLEANUP_SP1_SECRET_ARN="$sp1_secret_arn"
    ok "SP1 secret created: $sp1_secret_arn"
  fi

  generate_tfvars "$tfvars_file" "$deployment_id" "$ssh_cidr" "$pg_password" "$sp1_secret_arn"

  log "running terraform init..."
  tf_cmd -chdir="$TERRAFORM_DIR" init -input=false >/dev/null

  log "running terraform apply (this takes 10-20 minutes)..."
  tf_cmd -chdir="$TERRAFORM_DIR" apply \
    -input=false -auto-approve \
    -state="$state_file" \
    -var-file="$tfvars_file" \
    2>&1 | tee "$WORKDIR/logs/terraform-apply.log"

  ok "Terraform apply completed"
}

read_tf_outputs() {
  step "Reading Terraform outputs"

  local state_file="$WORKDIR/infra/terraform.tfstate"
  [[ -f "$state_file" ]] || die "terraform state not found: $state_file"

  # Resolve to absolute path so -chdir doesn't break the -state reference.
  state_file="$(cd "$(dirname "$state_file")" && pwd)/$(basename "$state_file")"

  # Ensure providers are initialised so `terraform output` can read the state.
  tf_cmd -chdir="$TERRAFORM_DIR" init -input=false -backend=false >/dev/null 2>&1 || true

  _tf_out() {
    tf_cmd -chdir="$TERRAFORM_DIR" output -state="$state_file" -raw "$1" 2>/dev/null || true
  }

  RUNNER_PUBLIC_IP="$(_tf_out runner_public_ip)"
  RUNNER_SSH_USER="$(_tf_out runner_ssh_user)"
  [[ -n "$RUNNER_PUBLIC_IP" ]] || die "runner_public_ip is empty"
  ok "Runner: $RUNNER_SSH_USER@$RUNNER_PUBLIC_IP"

  SHARED_POSTGRES_ENDPOINT="$(_tf_out shared_postgres_endpoint)"
  local pg_port; pg_port="$(_tf_out shared_postgres_port)"
  local pg_password; pg_password="$(cat "$WORKDIR/local-secrets/postgres-password.txt")"
  SHARED_POSTGRES_DSN="postgres://postgres:${pg_password}@${SHARED_POSTGRES_ENDPOINT}:${pg_port:-5432}/intents_e2e?sslmode=require"
  ok "Postgres: $SHARED_POSTGRES_ENDPOINT"

  SHARED_KAFKA_BROKERS="$(_tf_out shared_kafka_bootstrap_brokers)"
  ok "Kafka: ${SHARED_KAFKA_BROKERS:0:60}..."

  SHARED_IPFS_API_URL="$(_tf_out shared_ipfs_api_url)"
  ok "IPFS: $SHARED_IPFS_API_URL"

  SHARED_ECS_CLUSTER_ARN="$(_tf_out shared_ecs_cluster_arn)"
  SHARED_PROOF_REQUESTOR_SERVICE="$(_tf_out shared_proof_requestor_service_name)"
  SHARED_PROOF_FUNDER_SERVICE="$(_tf_out shared_proof_funder_service_name)"
  ok "ECS cluster: $SHARED_ECS_CLUSTER_ARN"

  DKG_KMS_KEY_ARN="$(_tf_out dkg_kms_key_arn)"
  DKG_S3_BUCKET="$(_tf_out dkg_s3_bucket)"
  DKG_S3_KEY_PREFIX="$(_tf_out dkg_s3_key_prefix)"
  ok "DKG: bucket=$DKG_S3_BUCKET kms=$DKG_KMS_KEY_ARN"

  # Operator IPs (JSON arrays)
  local pub_json priv_json
  pub_json="$(tf_cmd -chdir="$TERRAFORM_DIR" output -state="$state_file" -json operator_public_ips 2>/dev/null)"
  priv_json="$(tf_cmd -chdir="$TERRAFORM_DIR" output -state="$state_file" -json operator_private_ips 2>/dev/null)"
  mapfile -t OPERATOR_PUBLIC_IPS < <(jq -r '.[]' <<<"$pub_json")
  mapfile -t OPERATOR_PRIVATE_IPS < <(jq -r '.[]' <<<"$priv_json")
  ok "Operators: ${#OPERATOR_PUBLIC_IPS[@]} hosts (${OPERATOR_PUBLIC_IPS[0]}, ...)"
}

# ── SSH helpers ──────────────────────────────────────────────────────────────

wait_for_ssh() {
  local host="$1" user="$2" max_attempts="${3:-60}"
  log "waiting for SSH on $user@$host..."
  local attempt=0
  while (( attempt < max_attempts )); do
    if ssh "${SSH_OPTS[@]}" "$user@$host" "true" 2>/dev/null; then
      ok "SSH ready: $user@$host"
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 10
  done
  die "SSH not ready after ${max_attempts} attempts: $user@$host"
}

run_on_host() {
  local host="$1"; shift
  local cmd="$*"
  # Use base64-encoded payload to avoid quoting issues with '!' and special chars.
  # Prepend PATH and cargo env since bash non-interactive login skips .bashrc guard.
  local preamble='export PATH="$HOME/.foundry/bin:$PATH:/usr/local/go/bin:$HOME/go/bin"
[ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"
'
  local encoded
  encoded="$(printf '%s\n%s' "$preamble" "$cmd" | base64)"
  ssh "${SSH_OPTS[@]}" "$RUNNER_SSH_USER@$host" \
    "echo '$encoded' | base64 -d | bash"
}

scp_to_host() {
  local host="$1" local_path="$2" remote_path="$3"
  scp "${SSH_OPTS[@]}" -q "$local_path" "$RUNNER_SSH_USER@$host:$remote_path"
}

scp_from_host() {
  local host="$1" remote_path="$2" local_path="$3"
  scp "${SSH_OPTS[@]}" -q "$RUNNER_SSH_USER@$host:$remote_path" "$local_path"
}

# ── Host preparation ────────────────────────────────────────────────────────

prepare_runner_host() {
  step "Preparing runner host"

  wait_for_ssh "$RUNNER_PUBLIC_IP" "$RUNNER_SSH_USER" 90

  local setup_script
  setup_script="$(cat <<'SCRIPT'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# Wait for cloud-init
cloud-init status --wait >/dev/null 2>&1 || true

# Install dependencies
sudo apt-get update -y
sudo apt-get install -y \
  build-essential git jq curl unzip rsync age \
  ca-certificates postgresql-client-16 2>/dev/null || \
  sudo apt-get install -y \
  build-essential git jq curl unzip rsync age \
  ca-certificates postgresql-client

# Install Go if not present
if ! command -v go >/dev/null 2>&1; then
  GO_VERSION="1.22.8"
  curl -sfL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | sudo tar -C /usr/local -xzf -
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
  export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
fi
go version

# Install Rust if not present (needed for ufvk-derive-keys)
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
fi

# Install Foundry (cast, forge) if not present
export PATH="$HOME/.foundry/bin:$PATH"
if ! command -v cast >/dev/null 2>&1; then
  curl -L https://foundry.paradigm.xyz | bash
  export PATH="$HOME/.foundry/bin:$PATH"
  foundryup
fi

# Install juno-txsign if not present
if ! command -v juno-txsign >/dev/null 2>&1; then
  _rel_json="$(curl -fsSL https://api.github.com/repos/junocash-tools/juno-txsign/releases/latest)"
  _rel_tag="$(echo "$_rel_json" | jq -r '.tag_name // empty')"
  _asset="juno-txsign_${_rel_tag}_linux_amd64.tar.gz"
  _url="$(echo "$_rel_json" | jq -r --arg n "$_asset" '.assets[] | select(.name == $n) | .browser_download_url' | head -n 1)"
  _tmp="$(mktemp)" && _dir="$(mktemp -d)"
  curl -fsSL "$_url" -o "$_tmp" && tar -xzf "$_tmp" -C "$_dir"
  sudo install -m 0755 "$_dir/juno-txsign" /usr/local/bin/juno-txsign
  rm -f "$_tmp" && rm -rf "$_dir"
fi
SCRIPT
  )"
  run_on_host "$RUNNER_PUBLIC_IP" "$setup_script"

  # Clone or update repo
  local repo_url
  repo_url="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || echo "https://github.com/juno-intents/intents-juno.git")"
  local current_commit
  current_commit="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "main")"

  local clone_script
  clone_script="$(cat <<CLONESCRIPT
set -euo pipefail
REMOTE_REPO="\$HOME/intents-juno"
if [[ -d "\$REMOTE_REPO/.git" ]]; then
  cd "\$REMOTE_REPO"
  git fetch origin --prune
  git checkout "$current_commit" 2>/dev/null || git checkout origin/main
else
  git clone "$repo_url" "\$REMOTE_REPO"
  cd "\$REMOTE_REPO"
  git checkout "$current_commit" 2>/dev/null || true
fi
CLONESCRIPT
  )"
  run_on_host "$RUNNER_PUBLIC_IP" "$clone_script"
  ok "Runner prepared"
}

prepare_operator_hosts() {
  step "Preparing operator hosts"

  for i in "${!OPERATOR_PUBLIC_IPS[@]}"; do
    local op_ip="${OPERATOR_PUBLIC_IPS[$i]}"
    log "preparing operator $((i+1))/${#OPERATOR_PUBLIC_IPS[@]}: $op_ip"

    wait_for_ssh "$op_ip" "$RUNNER_SSH_USER" 60

    # Use heredoc-over-SSH to avoid quoting issues with '!'
    ssh "${SSH_OPTS[@]}" "$RUNNER_SSH_USER@$op_ip" bash -s <<'OPSCRIPT'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

cloud-init status --wait >/dev/null 2>&1 || true

# Validate AMI has required systemd services
missing=0
for svc in junocashd.service juno-scan.service; do
  if ! sudo systemctl cat "$svc" >/dev/null 2>&1; then
    echo "ERROR: missing systemd unit: $svc" >&2
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then exit 1; fi

# Normalize stack config file access
sudo install -d -m 0750 -o root -g ubuntu /etc/intents-juno
for f in /etc/intents-juno/junocashd.conf /etc/intents-juno/operator-stack.env /etc/intents-juno/checkpoint-signer.key; do
  if [ -f "$f" ]; then
    sudo chgrp ubuntu "$f"
    sudo chmod 0640 "$f"
  fi
done

# Start junocashd and juno-scan
sudo systemctl daemon-reload
sudo systemctl enable junocashd.service juno-scan.service
sudo systemctl restart junocashd.service

# Wait for junocashd to be fully ready (wallet loaded)
echo "waiting for junocashd to finish loading..."
for i in $(seq 1 60); do
  if sudo -u ubuntu junocash-cli -conf=/etc/intents-juno/junocashd.conf getblockchaininfo >/dev/null 2>&1; then
    echo "junocashd RPC ready after ${i}s"
    break
  fi
  if [ "$i" -eq 60 ]; then
    echo "ERROR: junocashd RPC not ready after 60s" >&2
    sudo journalctl -u junocashd.service --no-pager -n 20 >&2
    exit 1
  fi
  sleep 1
done

# Now start juno-scan (it needs junocashd RPC ready)
sudo systemctl restart juno-scan.service
sleep 2
if ! systemctl is-active --quiet juno-scan.service; then
  echo "WARNING: juno-scan not yet active, will auto-restart via systemd" >&2
fi

echo "operator host ready"
OPSCRIPT
    ok "Operator $((i+1)) ready ($op_ip)"
  done
}

# ── RPC credential extraction ───────────────────────────────────────────────

extract_rpc_credentials() {
  step "Extracting Juno RPC credentials from operator"

  local secrets_dir="$WORKDIR/local-secrets"
  local rpc_user_file="$secrets_dir/juno-rpc-user.txt"
  local rpc_pass_file="$secrets_dir/juno-rpc-pass.txt"

  if [[ -f "$rpc_user_file" && -f "$rpc_pass_file" ]]; then
    ok "reusing cached RPC credentials"
    return 0
  fi

  local op_ip="${OPERATOR_PUBLIC_IPS[0]}"
  local creds
  creds="$(run_on_host "$op_ip" \
    "sudo grep -E '^JUNO_RPC_(USER|PASS)=' /etc/intents-juno/operator-stack.env 2>/dev/null || \
     echo 'JUNO_RPC_USER=juno'; echo 'JUNO_RPC_PASS='"
  )"

  local rpc_user rpc_pass
  rpc_user="$(grep '^JUNO_RPC_USER=' <<<"$creds" | cut -d= -f2 | tr -d '\r\n')"
  rpc_pass="$(grep '^JUNO_RPC_PASS=' <<<"$creds" | cut -d= -f2 | tr -d '\r\n')"

  [[ -n "$rpc_user" ]] || rpc_user="juno"
  [[ -n "$rpc_pass" ]] || die "could not extract JUNO_RPC_PASS from operator ${op_ip}"

  echo -n "$rpc_user" > "$rpc_user_file"
  echo -n "$rpc_pass" > "$rpc_pass_file"
  chmod 600 "$rpc_user_file" "$rpc_pass_file"
  ok "RPC credentials extracted (user=$rpc_user)"
}

# ── DKG ceremony (distributed, via runner) ───────────────────────────────────

run_distributed_dkg() {
  step "Running distributed DKG ceremony"

  local dkg_summary="$WORKDIR/reports/dkg-summary.json"
  if [[ -f "$dkg_summary" ]]; then
    ok "reusing existing DKG summary: $dkg_summary"
    return 0
  fi

  # Fresh DKG will produce new operator keys — any stale bridge summary from a
  # previous run is no longer valid (operator addresses won't match).
  local stale_bridge_summary="$WORKDIR/reports/base-bridge-summary.json"
  if [[ -f "$stale_bridge_summary" ]]; then
    warn "removing stale bridge summary (new DKG will generate different operator keys)"
    rm -f "$stale_bridge_summary"
  fi

  mkdir -p "$WORKDIR/reports"

  # Build the operator fleet SSH access script (SCP SSH key to runner)
  local remote_ssh_key="/home/$RUNNER_SSH_USER/.ssh/fleet_ed25519"
  scp_to_host "$RUNNER_PUBLIC_IP" "$SSH_KEY_PRIVATE" "$remote_ssh_key"
  run_on_host "$RUNNER_PUBLIC_IP" "chmod 600 $remote_ssh_key"

  # Build operator registration info on runner
  local op_private_ips_csv=""
  for ip in "${OPERATOR_PRIVATE_IPS[@]}"; do
    op_private_ips_csv="${op_private_ips_csv:+$op_private_ips_csv,}$ip"
  done

  local dkg_script
  dkg_script="$(cat <<DKGSCRIPT
set -euo pipefail
export PATH="\$PATH:/usr/local/go/bin:\$HOME/go/bin"
source "\$HOME/.cargo/env" 2>/dev/null || true
cd "\$HOME/intents-juno"

WORKDIR="\$HOME/e2e-dkg"
mkdir -p "\$WORKDIR/reports"

# Run the DKG backup-restore ceremony
deploy/operators/dkg/e2e/run-dkg-backup-restore.sh run \\
  --workdir "\$WORKDIR" \\
  --operator-count $OPERATOR_COUNT \\
  --threshold $OPERATOR_THRESHOLD \\
  --base-port $OPERATOR_BASE_PORT \\
  --output "\$WORKDIR/reports/dkg-summary.json" \\
  --force

cat "\$WORKDIR/reports/dkg-summary.json"
DKGSCRIPT
  )"

  # For distributed DKG, we need to configure the runner to SSH to operators.
  # The run-dkg-backup-restore.sh handles local DKG (all operators on localhost).
  # For distributed, we use the run-testnet-e2e-aws.sh DKG flow which SSHes to operators.
  # Since we're setting up our own flow, run the distributed DKG via the coordinator scripts.

  local reg_dir="/home/$RUNNER_SSH_USER/e2e-dkg/registrations"
  local coord_dir="/home/$RUNNER_SSH_USER/e2e-dkg/coordinator"
  local dkg_dir="/home/$RUNNER_SSH_USER/e2e-dkg"

  # Step 1: Generate operator keys on each operator host
  local -a operator_ids=()
  local -a operator_key_files=()
  for i in "${!OPERATOR_PRIVATE_IPS[@]}"; do
    local op_pub="${OPERATOR_PUBLIC_IPS[$i]}"
    local op_priv="${OPERATOR_PRIVATE_IPS[$i]}"
    local port=$((OPERATOR_BASE_PORT + i))

    # Generate operator key on the runner
    local keygen_output
    keygen_output="$(run_on_host "$RUNNER_PUBLIC_IP" \
      "cd /home/$RUNNER_SSH_USER/intents-juno && \
       go run ./cmd/operator-keygen -private-key-path /home/$RUNNER_SSH_USER/e2e-dkg/op$((i+1))/key.hex"
    )"

    local op_id
    op_id="$(echo "$keygen_output" | jq -r '.operator_id // empty' 2>/dev/null || true)"
    [[ -n "$op_id" ]] || die "failed to generate operator key for operator $((i+1))"
    operator_ids+=("$op_id")
    operator_key_files+=("/home/$RUNNER_SSH_USER/e2e-dkg/op$((i+1))/key.hex")

    # Create registration JSON
    run_on_host "$RUNNER_PUBLIC_IP" "mkdir -p $reg_dir && cat > $reg_dir/op$((i+1)).json <<EOF
{
  \"operator_id\": \"$op_id\",
  \"fee_recipient\": \"$op_id\",
  \"grpc_endpoint\": \"https://$op_priv:$port\"
}
EOF"
    log "  operator $((i+1)): $op_id @ $op_priv:$port"
  done

  # Step 2: Run coordinator init
  local reg_args=""
  for i in $(seq 1 "$OPERATOR_COUNT"); do
    reg_args="$reg_args --registration-file $reg_dir/op${i}.json"
  done

  run_on_host "$RUNNER_PUBLIC_IP" "cd /home/$RUNNER_SSH_USER/intents-juno && \
    deploy/operators/dkg/coordinator.sh init \
      --workdir $coord_dir \
      --network testnet \
      --threshold $OPERATOR_THRESHOLD \
      --max-signers $OPERATOR_COUNT \
      --release-tag $DKG_RELEASE_TAG \
      $reg_args"
  ok "DKG coordinator initialized"

  # Step 3: Distribute bundles to operators and start operator DKG processes
  for i in "${!OPERATOR_PUBLIC_IPS[@]}"; do
    local op_pub="${OPERATOR_PUBLIC_IPS[$i]}"
    local op_id="${operator_ids[$i]}"
    # Find the bundle for this operator (bundles named like N_0xADDR.tar.gz)
    local bundle_path
    bundle_path="$(run_on_host "$RUNNER_PUBLIC_IP" \
      "ls $coord_dir/bundles/*_${op_id}.tar.gz 2>/dev/null | head -1"
    )"
    [[ -n "$bundle_path" ]] || die "no DKG bundle found for operator $((i+1)) ($op_id)"

    # SCP bundle from runner to operator (via runner as jump host)
    local op_runtime="/home/$RUNNER_SSH_USER/operator-runtime"
    run_on_host "$RUNNER_PUBLIC_IP" \
      "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -i $remote_ssh_key \
       '$bundle_path' $RUNNER_SSH_USER@${OPERATOR_PRIVATE_IPS[$i]}:/tmp/dkg-bundle.tar.gz"

    # Stop any existing dkg-admin, then start fresh
    # JUNO_DKG_NETWORK_MODE=vpc-private bypasses Tailscale check (operators use VPC private IPs)
    run_on_host "$RUNNER_PUBLIC_IP" \
      "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -i $remote_ssh_key $RUNNER_SSH_USER@${OPERATOR_PRIVATE_IPS[$i]} \
       'export JUNO_DKG_NETWORK_MODE=vpc-private && \
        cd /home/$RUNNER_SSH_USER/intents-juno 2>/dev/null || cd \$HOME && \
        deploy/operators/dkg/operator.sh stop --workdir $op_runtime >/dev/null 2>&1 || true && \
        rm -rf $op_runtime && \
        mkdir -p $op_runtime && \
        deploy/operators/dkg/operator.sh run \
          --bundle /tmp/dkg-bundle.tar.gz \
          --workdir $op_runtime \
          --release-tag $DKG_RELEASE_TAG \
          --daemon'"
    ok "DKG operator $((i+1)) started"
  done

  # Step 4: Run coordinator ceremony (vpc-private mode for all DKG scripts)
  # Preflight may need retries while operators finish starting up
  local preflight_attempts=0
  while true; do
    preflight_attempts=$((preflight_attempts + 1))
    if run_on_host "$RUNNER_PUBLIC_IP" "export JUNO_DKG_NETWORK_MODE=vpc-private && \
        cd /home/$RUNNER_SSH_USER/intents-juno && \
        deploy/operators/dkg/coordinator.sh preflight \
          --workdir $coord_dir --release-tag $DKG_RELEASE_TAG" 2>&1; then
      break
    fi
    if [[ $preflight_attempts -ge 10 ]]; then
      die "DKG coordinator preflight failed after $preflight_attempts attempts"
    fi
    log "preflight attempt $preflight_attempts failed, retrying in 10s..."
    sleep 10
  done
  ok "DKG preflight passed"

  run_on_host "$RUNNER_PUBLIC_IP" "export JUNO_DKG_NETWORK_MODE=vpc-private && \
    cd /home/$RUNNER_SSH_USER/intents-juno && \
    deploy/operators/dkg/coordinator.sh run \
      --workdir $coord_dir --release-tag $DKG_RELEASE_TAG"
  ok "DKG ceremony completed"

  # Step 5: Run completion test and extract UFVK
  run_on_host "$RUNNER_PUBLIC_IP" "export JUNO_DKG_NETWORK_MODE=vpc-private && \
    cd /home/$RUNNER_SSH_USER/intents-juno && \
    deploy/operators/dkg/test-completiton.sh run \
      --workdir $coord_dir \
      --skip-resume \
      --release-tag $DKG_RELEASE_TAG \
      --output $dkg_dir/reports/completion.json"

  # Step 6: Build DKG summary
  local completion_json
  completion_json="$(run_on_host "$RUNNER_PUBLIC_IP" "cat $dkg_dir/reports/completion.json")"
  local ufvk
  ufvk="$(jq -r '.ufvk // empty' <<<"$completion_json")"
  [[ -n "$ufvk" ]] || die "DKG completion report missing ufvk"

  local juno_shielded_address
  juno_shielded_address="$(jq -r '.juno_shielded_address // empty' <<<"$completion_json")"

  # Build summary JSON and save locally
  local operator_ids_json="[]"
  local operator_keys_json="[]"
  for i in "${!operator_ids[@]}"; do
    operator_ids_json="$(jq --arg id "${operator_ids[$i]}" '. + [$id]' <<<"$operator_ids_json")"
    operator_keys_json="$(jq --arg kf "${operator_key_files[$i]}" '. + [$kf]' <<<"$operator_keys_json")"
  done

  # Build operator endpoints for the summary (TSS gRPC endpoints on VPC IPs)
  local operator_endpoints_json="[]"
  for i in "${!OPERATOR_PRIVATE_IPS[@]}"; do
    local port=$((OPERATOR_BASE_PORT + i))
    operator_endpoints_json="$(jq --arg ep "https://${OPERATOR_PRIVATE_IPS[$i]}:$port" '. + [$ep]' <<<"$operator_endpoints_json")"
  done

  jq -n \
    --arg ufvk "$ufvk" \
    --arg juno_shielded_address "$juno_shielded_address" \
    --argjson operator_ids "$operator_ids_json" \
    --argjson operator_key_files "$operator_keys_json" \
    --argjson operator_endpoints "$operator_endpoints_json" \
    --arg coordinator_workdir "$coord_dir" \
    --argjson threshold "$OPERATOR_THRESHOLD" \
    '{
      ufvk: $ufvk,
      juno_shielded_address: $juno_shielded_address,
      operator_count: ($operator_ids | length),
      threshold: $threshold,
      operators: [range($operator_ids | length) | {
        operator_id: $operator_ids[.],
        operator_key_file: $operator_key_files[.],
        endpoint: $operator_endpoints[.]
      }],
      coordinator_workdir: $coordinator_workdir,
      completion_report: "'"$dkg_dir"'/reports/completion.json"
    }' > "$dkg_summary"

  ok "DKG summary saved: $dkg_summary"
  ok "UFVK: ${ufvk:0:32}..."
  ok "Juno shielded address: ${juno_shielded_address:0:40}..."

  # Step 7: Backup/restore and KMS export for each operator
  for i in "${!OPERATOR_PUBLIC_IPS[@]}"; do
    local op_priv="${OPERATOR_PRIVATE_IPS[$i]}"
    local op_runtime="/home/$RUNNER_SSH_USER/operator-runtime"

    # KMS export via runner -> operator SSH
    run_on_host "$RUNNER_PUBLIC_IP" \
      "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -i $remote_ssh_key $RUNNER_SSH_USER@$op_priv \
       'cd /home/$RUNNER_SSH_USER/intents-juno 2>/dev/null || cd \$HOME && \
        deploy/operators/dkg/operator-export-kms.sh export \
          --workdir $op_runtime \
          --release-tag $DKG_RELEASE_TAG \
          --kms-key-id $DKG_KMS_KEY_ARN \
          --s3-bucket $DKG_S3_BUCKET \
          --s3-key-prefix $DKG_S3_KEY_PREFIX \
          --s3-sse-kms-key-id $DKG_KMS_KEY_ARN \
          --aws-region $AWS_REGION \
          --skip-aws-preflight'"
    ok "Operator $((i+1)) KMS export done"
  done
}

# ── Derive owallet keys from UFVK ───────────────────────────────────────────

derive_owallet_keys() {
  step "Deriving owallet keys from UFVK"

  local dkg_summary="$WORKDIR/reports/dkg-summary.json"
  local ufvk
  ufvk="$(jq -r '.ufvk' "$dkg_summary")"

  local derive_output
  derive_output="$(run_on_host "$RUNNER_PUBLIC_IP" \
    "cd /home/$RUNNER_SSH_USER/intents-juno && \
     source \$HOME/.cargo/env 2>/dev/null || true && \
     cargo run --quiet --manifest-path deploy/operators/dkg/e2e/ufvk-derive-keys/Cargo.toml -- '$ufvk'"
  )"

  SP1_DEPOSIT_OWALLET_IVK_HEX="$(grep '^SP1_DEPOSIT_OWALLET_IVK_HEX=' <<<"$derive_output" | cut -d= -f2)"
  SP1_WITHDRAW_OWALLET_OVK_HEX="$(grep '^SP1_WITHDRAW_OWALLET_OVK_HEX=' <<<"$derive_output" | cut -d= -f2)"

  [[ -n "$SP1_DEPOSIT_OWALLET_IVK_HEX" ]] || die "failed to derive deposit owallet IVK"
  [[ -n "$SP1_WITHDRAW_OWALLET_OVK_HEX" ]] || die "failed to derive withdraw owallet OVK"
  ok "deposit IVK: ${SP1_DEPOSIT_OWALLET_IVK_HEX:0:20}..."
  ok "withdraw OVK: ${SP1_WITHDRAW_OWALLET_OVK_HEX:0:20}..."
}

# ── Stage secrets on runner ──────────────────────────────────────────────────

stage_secrets_on_runner() {
  step "Staging secrets on runner"

  local remote_secrets="/home/$RUNNER_SSH_USER/.ci/secrets"
  run_on_host "$RUNNER_PUBLIC_IP" "mkdir -p $remote_secrets && chmod 700 $remote_secrets"

  # Base funder key
  scp_to_host "$RUNNER_PUBLIC_IP" "$BASE_FUNDER_KEY_FILE" "$remote_secrets/base-funder.key"

  # Juno funder
  if [[ -n "$JUNO_FUNDER_SEED_FILE" ]]; then
    scp_to_host "$RUNNER_PUBLIC_IP" "$JUNO_FUNDER_SEED_FILE" "$remote_secrets/juno-funder-seed.txt"
  fi
  if [[ -n "${JUNO_FUNDER_KEY_FILE:-}" ]]; then
    scp_to_host "$RUNNER_PUBLIC_IP" "$JUNO_FUNDER_KEY_FILE" "$remote_secrets/juno-funder.key"
  fi
  if [[ -n "${JUNO_FUNDER_SOURCE_ADDRESS_FILE:-}" ]]; then
    scp_to_host "$RUNNER_PUBLIC_IP" "$JUNO_FUNDER_SOURCE_ADDRESS_FILE" "$remote_secrets/juno-funder-source-address.txt"
  fi

  # Juno RPC credentials
  scp_to_host "$RUNNER_PUBLIC_IP" "$WORKDIR/local-secrets/juno-rpc-user.txt" "$remote_secrets/juno-rpc-user.txt"
  scp_to_host "$RUNNER_PUBLIC_IP" "$WORKDIR/local-secrets/juno-rpc-pass.txt" "$remote_secrets/juno-rpc-pass.txt"

  # SP1 requestor key
  scp_to_host "$RUNNER_PUBLIC_IP" "$SP1_REQUESTOR_KEY_FILE" "$remote_secrets/sp1-requestor.key"

  # SSH fleet key (for runner -> operator access)
  scp_to_host "$RUNNER_PUBLIC_IP" "$SSH_KEY_PRIVATE" "$remote_secrets/fleet-ssh-key"
  run_on_host "$RUNNER_PUBLIC_IP" "chmod 600 $remote_secrets/fleet-ssh-key"

  ok "All secrets staged on runner"
}

# ── Provision operator-stack-config.json on each operator ────────────────────

provision_operator_stack_config() {
  step "Provisioning operator-stack-config.json on operators"

  local dkg_summary="$WORKDIR/reports/dkg-summary.json"
  [[ -f "$dkg_summary" ]] || die "DKG summary not found: $dkg_summary"

  local checkpoint_operators_csv
  checkpoint_operators_csv="$(jq -r '[.operators[].operator_id] | join(",")' "$dkg_summary")"
  [[ -n "$checkpoint_operators_csv" ]] || die "failed to derive checkpoint operator set"

  local dkg_ufvk
  dkg_ufvk="$(jq -r '.ufvk // empty' "$dkg_summary")"
  [[ -n "$dkg_ufvk" ]] || die "DKG summary missing .ufvk"

  local config_json
  config_json="$(jq -n \
    --arg checkpoint_postgres_dsn "$SHARED_POSTGRES_DSN" \
    --arg checkpoint_kafka_brokers "$SHARED_KAFKA_BROKERS" \
    --arg checkpoint_ipfs_api_url "$SHARED_IPFS_API_URL" \
    --arg checkpoint_blob_bucket "$DKG_S3_BUCKET" \
    --arg checkpoint_blob_prefix "checkpoint-packages" \
    --arg checkpoint_operators "$checkpoint_operators_csv" \
    --arg checkpoint_threshold "$OPERATOR_THRESHOLD" \
    '{
      CHECKPOINT_POSTGRES_DSN: $checkpoint_postgres_dsn,
      CHECKPOINT_KAFKA_BROKERS: $checkpoint_kafka_brokers,
      CHECKPOINT_IPFS_API_URL: $checkpoint_ipfs_api_url,
      CHECKPOINT_BLOB_BUCKET: $checkpoint_blob_bucket,
      CHECKPOINT_BLOB_PREFIX: $checkpoint_blob_prefix,
      CHECKPOINT_OPERATORS: $checkpoint_operators,
      CHECKPOINT_THRESHOLD: $checkpoint_threshold,
      CHECKPOINT_SIGNATURE_TOPIC: "checkpoints.signatures.v1",
      CHECKPOINT_PACKAGE_TOPIC: "checkpoints.packages.v1",
      JUNO_QUEUE_KAFKA_TLS: "true"
    }'
  )"

  for i in "${!OPERATOR_PUBLIC_IPS[@]}"; do
    local op_ip="${OPERATOR_PUBLIC_IPS[$i]}"
    log "provisioning operator-stack-config.json on operator $((i+1)): $op_ip"
    ssh "${SSH_OPTS[@]}" "$RUNNER_SSH_USER@$op_ip" bash -s <<CFGSCRIPT
set -euo pipefail
tmp_json="\$(mktemp)"
cat > "\$tmp_json" <<'JSONEOF'
${config_json}
JSONEOF
sudo install -d -m 0750 -o root -g ubuntu /etc/intents-juno
sudo install -m 0640 -o root -g ubuntu "\$tmp_json" /etc/intents-juno/operator-stack-config.json
rm -f "\$tmp_json"
# Force host-process mode (e2e instances are not nitro enclaves)
if grep -q '^TSS_SIGNER_RUNTIME_MODE=' /etc/intents-juno/operator-stack.env 2>/dev/null; then
  sudo sed -i 's/^TSS_SIGNER_RUNTIME_MODE=.*/TSS_SIGNER_RUNTIME_MODE=host-process/' /etc/intents-juno/operator-stack.env
fi
# Ensure /var/lib/intents-juno/operator-runtime symlinks to the DKG output path
if [[ ! -L /var/lib/intents-juno/operator-runtime ]] && [[ -d /home/ubuntu/operator-runtime ]]; then
  sudo rm -rf /var/lib/intents-juno/operator-runtime
  sudo ln -s /home/ubuntu/operator-runtime /var/lib/intents-juno/operator-runtime
fi
# Ensure ufvk.txt exists for tss-host signer
if [[ ! -s /home/ubuntu/operator-runtime/ufvk.txt ]]; then
  printf '%s\n' '${dkg_ufvk}' > /home/ubuntu/operator-runtime/ufvk.txt
  chmod 0600 /home/ubuntu/operator-runtime/ufvk.txt
fi
echo "ok"
CFGSCRIPT
  done

  ok "operator-stack-config.json deployed to all ${#OPERATOR_PUBLIC_IPS[@]} operators"
}

# ── Scale ECS proof services ─────────────────────────────────────────────────

scale_proof_services() {
  local desired="$1"
  step "Scaling ECS proof services to desired=$desired"

  for svc in "$SHARED_PROOF_REQUESTOR_SERVICE" "$SHARED_PROOF_FUNDER_SERVICE"; do
    [[ -n "$svc" ]] || continue
    env AWS_PROFILE="$AWS_PROFILE" aws ecs update-service \
      --region "$AWS_REGION" \
      --cluster "$SHARED_ECS_CLUSTER_ARN" \
      --service "$svc" \
      --desired-count "$desired" \
      --query 'service.serviceName' --output text >/dev/null 2>&1 || \
      warn "failed to scale $svc to $desired"
  done
  ok "ECS services scaled"
}

# ── Deploy backoffice on runner ───────────────────────────────────────────────

deploy_backoffice() {
  step "Deploying backoffice on runner"

  # Generate auth token
  BACKOFFICE_AUTH_TOKEN="$(openssl rand -hex 24)"

  # Cross-compile backoffice for linux/amd64
  log "building backoffice for linux/amd64..."
  GOOS=linux GOARCH=amd64 go build -o "$WORKDIR/bin/backoffice-linux-amd64" ./cmd/backoffice/
  ok "backoffice binary built"

  # Kill any running backoffice so the binary can be replaced.
  run_on_host "$RUNNER_PUBLIC_IP" \
    "pkill -f '/home/$RUNNER_SSH_USER/bin/backoffice' 2>/dev/null || true; sleep 1"

  # SCP to runner
  run_on_host "$RUNNER_PUBLIC_IP" "mkdir -p /home/$RUNNER_SSH_USER/bin"
  scp_to_host "$RUNNER_PUBLIC_IP" "$WORKDIR/bin/backoffice-linux-amd64" "/home/$RUNNER_SSH_USER/bin/backoffice"
  run_on_host "$RUNNER_PUBLIC_IP" "chmod +x /home/$RUNNER_SSH_USER/bin/backoffice"

  # Add security group ingress rule for backoffice port
  local my_ip
  my_ip="$(curl -sf https://checkip.amazonaws.com | tr -d '\r\n')" || true
  if [[ -n "$my_ip" ]]; then
    local runner_sg_id
    runner_sg_id="$(
      env AWS_PROFILE="$AWS_PROFILE" aws ec2 describe-instances \
        --region "$AWS_REGION" \
        --filters "Name=ip-address,Values=$RUNNER_PUBLIC_IP" \
        --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' \
        --output text 2>/dev/null || true
    )"
    if [[ -n "$runner_sg_id" && "$runner_sg_id" != "None" ]]; then
      env AWS_PROFILE="$AWS_PROFILE" aws ec2 authorize-security-group-ingress \
        --region "$AWS_REGION" \
        --group-id "$runner_sg_id" \
        --protocol tcp --port "$BACKOFFICE_PORT" \
        --cidr "0.0.0.0/0" \
        --tag-specifications "ResourceType=security-group-rule,Tags=[{Key=Name,Value=backoffice-e2e}]" \
        >/dev/null 2>&1 || warn "backoffice SG rule may already exist"
      BACKOFFICE_SG_RULE_ADDED=true
      ok "security group $runner_sg_id: opened port $BACKOFFICE_PORT"
    fi
  fi

  # Extract contract and operator addresses from bridge summary (if available).
  # The bridge summary contains the on-chain registered operator addresses which
  # differ from the DKG operator IDs (TSS signing keys).
  local operator_addrs=""
  local bo_bridge_address="" bo_wjuno_address="" bo_operator_registry_address="" bo_fee_distributor_address=""
  local bridge_summary_file="$WORKDIR/reports/base-bridge-summary.json"
  if [[ -f "$bridge_summary_file" ]]; then
    bo_bridge_address="$(jq -r '.contracts.bridge // empty' "$bridge_summary_file" 2>/dev/null || true)"
    bo_wjuno_address="$(jq -r '.contracts.wjuno // empty' "$bridge_summary_file" 2>/dev/null || true)"
    bo_operator_registry_address="$(jq -r '.contracts.operator_registry // empty' "$bridge_summary_file" 2>/dev/null || true)"
    bo_fee_distributor_address="$(jq -r '.contracts.fee_distributor // empty' "$bridge_summary_file" 2>/dev/null || true)"
    operator_addrs="$(jq -r '.operators | join(",")' "$bridge_summary_file" 2>/dev/null || true)"
  fi
  # Fallback to DKG summary if bridge summary has no operators
  if [[ -z "$operator_addrs" && -f "$WORKDIR/reports/dkg-summary.json" ]]; then
    operator_addrs="$(jq -r '[.operators[].operator_id] | join(",")' "$WORKDIR/reports/dkg-summary.json" 2>/dev/null || true)"
  fi

  # Start backoffice on runner (background, nohup)
  local backoffice_cmd
  backoffice_cmd="/home/$RUNNER_SSH_USER/bin/backoffice"
  backoffice_cmd+=" --listen 0.0.0.0:${BACKOFFICE_PORT}"
  backoffice_cmd+=" --postgres-dsn '${SHARED_POSTGRES_DSN}'"
  backoffice_cmd+=" --base-rpc-url '${BASE_RPC_URL}'"
  backoffice_cmd+=" --auth-secret '${BACKOFFICE_AUTH_TOKEN}'"
  if [[ -n "$operator_addrs" ]]; then
    backoffice_cmd+=" --operator-addresses '${operator_addrs}'"
  fi
  if [[ -n "$bo_bridge_address" ]]; then
    backoffice_cmd+=" --bridge-address '${bo_bridge_address}'"
  fi
  if [[ -n "$bo_wjuno_address" ]]; then
    backoffice_cmd+=" --wjuno-address '${bo_wjuno_address}'"
  fi
  if [[ -n "$bo_operator_registry_address" ]]; then
    backoffice_cmd+=" --operator-registry-address '${bo_operator_registry_address}'"
  fi
  if [[ -n "$bo_fee_distributor_address" ]]; then
    backoffice_cmd+=" --fee-distributor-address '${bo_fee_distributor_address}'"
  fi

  # SP1 requestor address and prover network RPC
  if [[ -n "$SP1_REQUESTOR_KEY_FILE" && -f "$SP1_REQUESTOR_KEY_FILE" ]]; then
    local sp1_requestor_addr
    sp1_requestor_addr="$(cast wallet address --private-key "$(tr -d '\r\n' < "$SP1_REQUESTOR_KEY_FILE")" 2>/dev/null || true)"
    if [[ -n "$sp1_requestor_addr" ]]; then
      backoffice_cmd+=" --sp1-requestor-address '${sp1_requestor_addr}'"
    fi
  fi
  if [[ -f "$bridge_summary_file" ]]; then
    local sp1_rpc_url
    sp1_rpc_url="$(jq -r '.proof.sp1.rpc_url // empty' "$bridge_summary_file" 2>/dev/null || true)"
    if [[ -n "$sp1_rpc_url" ]]; then
      backoffice_cmd+=" --sp1-rpc-url '${sp1_rpc_url}'"
    fi
  fi

  # Juno RPC (via SSH tunnel on first operator, port 38232)
  local juno_rpc_user_file="$WORKDIR/local-secrets/juno-rpc-user.txt"
  local juno_rpc_pass_file="$WORKDIR/local-secrets/juno-rpc-pass.txt"
  if [[ -f "$juno_rpc_user_file" && -f "$juno_rpc_pass_file" ]]; then
    backoffice_cmd+=" --juno-rpc-url 'http://127.0.0.1:38232'"
    backoffice_cmd+=" --juno-rpc-user '$(cat "$juno_rpc_user_file")'"
    backoffice_cmd+=" --juno-rpc-pass '$(cat "$juno_rpc_pass_file")'"
  fi

  # Bridge addresses are required by the binary. If unavailable (e.g. first run
  # before bridge deployment), deploy only the binary; the test script will
  # (re)start the backoffice after bridge deployment with correct addresses.
  if [[ -z "$bo_bridge_address" || -z "$bo_wjuno_address" || -z "$bo_operator_registry_address" ]]; then
    warn "backoffice: bridge addresses not yet available — binary deployed but process deferred until after bridge deployment"
  else
    run_on_host "$RUNNER_PUBLIC_IP" \
      "pkill -f '/home/$RUNNER_SSH_USER/bin/backoffice' 2>/dev/null || true; \
       sleep 1; \
       nohup $backoffice_cmd > /home/$RUNNER_SSH_USER/backoffice.log 2>&1 &"
    ok "backoffice started on runner"
  fi

  # Write access details to local tmp file
  local access_file="$REPO_ROOT/tmp/backoffice-access.txt"
  cat > "$access_file" <<ACCESS_EOF
# Backoffice Access Details (e2e run)
# Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)

URL:        http://${RUNNER_PUBLIC_IP}:${BACKOFFICE_PORT}
Auth Token: ${BACKOFFICE_AUTH_TOKEN}

# curl example:
curl -H "Authorization: Bearer ${BACKOFFICE_AUTH_TOKEN}" http://${RUNNER_PUBLIC_IP}:${BACKOFFICE_PORT}/api/ops/deposits/recent

# Dashboard (open in browser, enter token when prompted):
open http://${RUNNER_PUBLIC_IP}:${BACKOFFICE_PORT}

# Postgres DSN (for direct queries):
${SHARED_POSTGRES_DSN}
ACCESS_EOF
  chmod 600 "$access_file"
  ok "backoffice access details written to tmp/backoffice-access.txt"
  log "backoffice URL: http://${RUNNER_PUBLIC_IP}:${BACKOFFICE_PORT}"
}

# ── Run the e2e test on the runner ───────────────────────────────────────────

run_e2e_test() {
  step "Running e2e test on runner"

  local dkg_summary="$WORKDIR/reports/dkg-summary.json"
  local remote_secrets="/home/$RUNNER_SSH_USER/.ci/secrets"
  local remote_workdir="/home/$RUNNER_SSH_USER/testnet-e2e-live"
  local remote_repo="/home/$RUNNER_SSH_USER/intents-juno"

  # Build operator host list (use private IPs since runner is in the same VPC)
  local op_hosts_csv=""
  for ip in "${OPERATOR_PRIVATE_IPS[@]}"; do
    op_hosts_csv="${op_hosts_csv:+$op_hosts_csv,}$ip"
  done

  # Build operator IDs from DKG summary
  local operator_ids_csv=""
  operator_ids_csv="$(jq -r '[.operators[].operator_id] | join(",")' "$dkg_summary")"

  # Build the DKG summary path on runner
  local remote_dkg_summary="$remote_workdir/dkg-summary.json"
  run_on_host "$RUNNER_PUBLIC_IP" "mkdir -p $remote_workdir"
  scp_to_host "$RUNNER_PUBLIC_IP" "$dkg_summary" "$remote_dkg_summary"

  # If a bridge summary already exists from a previous run, reuse it to skip deploy.
  # IMPORTANT: Validate that the bridge's registered operators match the current DKG
  # summary. A mismatch (e.g. DKG was re-run but bridge was not redeployed) causes
  # silent failures — checkpoint signatures won't pass the on-chain isOperator() check.
  local bridge_summary_flag=""
  local bridge_summary="$WORKDIR/reports/base-bridge-summary.json"
  if [[ -f "$bridge_summary" ]]; then
    local bridge_ops dkg_ops
    bridge_ops="$(jq -r '[.operators[]? | ascii_downcase] | sort | join(",")' "$bridge_summary" 2>/dev/null || true)"
    dkg_ops="$(jq -r '[.operators[].operator_id | ascii_downcase] | sort | join(",")' "$dkg_summary" 2>/dev/null || true)"
    if [[ -n "$bridge_ops" && -n "$dkg_ops" && "$bridge_ops" != "$dkg_ops" ]]; then
      warn "bridge summary operators do not match DKG summary — forcing bridge redeploy"
      warn "  bridge: $bridge_ops"
      warn "  DKG:    $dkg_ops"
      rm -f "$bridge_summary"
    fi
  fi
  if [[ -f "$bridge_summary" ]]; then
    local remote_bridge_summary="$remote_workdir/reports/base-bridge-summary.json"
    run_on_host "$RUNNER_PUBLIC_IP" "mkdir -p $remote_workdir/reports"
    scp_to_host "$RUNNER_PUBLIC_IP" "$bridge_summary" "$remote_bridge_summary"
    bridge_summary_flag="--existing-bridge-summary-path $remote_bridge_summary"
    log "reusing existing bridge summary: $bridge_summary"
  fi

  # Resolve DKG juno shielded address
  local witness_recipient_ua
  witness_recipient_ua="$(jq -r '.juno_shielded_address' "$dkg_summary")"
  local witness_ufvk
  witness_ufvk="$(jq -r '.ufvk' "$dkg_summary")"

  # Build SSH tunnel ports for each operator (juno-scan, juno-rpc, tss)
  local tunnel_setup_script=""
  local witness_scan_urls=""
  local witness_rpc_urls=""
  local tss_urls=""
  for i in "${!OPERATOR_PRIVATE_IPS[@]}"; do
    local op_priv="${OPERATOR_PRIVATE_IPS[$i]}"
    local scan_port=$((38080 + i))
    local rpc_port=$((38232 + i))
    local tss_port=$((39443 + i))

    tunnel_setup_script+="ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
    tunnel_setup_script+="-i $remote_secrets/fleet-ssh-key "
    tunnel_setup_script+="-L ${scan_port}:127.0.0.1:8080 "
    tunnel_setup_script+="-L ${rpc_port}:127.0.0.1:18232 "
    tunnel_setup_script+="-L ${tss_port}:127.0.0.1:9443 "
    tunnel_setup_script+="-N $RUNNER_SSH_USER@$op_priv &"$'\n'
    tunnel_setup_script+="TUNNEL_PIDS+=(\$!)"$'\n'

    witness_scan_urls="${witness_scan_urls:+$witness_scan_urls,}http://127.0.0.1:${scan_port}"
    witness_rpc_urls="${witness_rpc_urls:+$witness_rpc_urls,}http://127.0.0.1:${rpc_port}"
    tss_urls="${tss_urls:+$tss_urls,}https://127.0.0.1:${tss_port}"
  done

  # Prepare environment variables
  local juno_rpc_user juno_rpc_pass
  juno_rpc_user="$(cat "$WORKDIR/local-secrets/juno-rpc-user.txt")"
  juno_rpc_pass="$(cat "$WORKDIR/local-secrets/juno-rpc-pass.txt")"

  # Build env exports for Juno funder
  local funder_env=""
  if [[ -n "$JUNO_FUNDER_SEED_FILE" ]]; then
    local seed_phrase
    seed_phrase="$(cat "$JUNO_FUNDER_SEED_FILE")"
    funder_env="export JUNO_FUNDER_SEED_PHRASE=$(printf '%q' "$seed_phrase")"
  elif [[ -n "${JUNO_FUNDER_KEY_FILE:-}" ]]; then
    local juno_key_hex
    juno_key_hex="$(cat "$JUNO_FUNDER_KEY_FILE")"
    funder_env="export JUNO_FUNDER_PRIVATE_KEY_HEX=$(printf '%q' "$juno_key_hex")"
  fi
  if [[ -n "${JUNO_FUNDER_SOURCE_ADDRESS_FILE:-}" ]]; then
    local funder_ua
    funder_ua="$(cat "$JUNO_FUNDER_SOURCE_ADDRESS_FILE")"
    funder_env+=$'\n'"export JUNO_FUNDER_SOURCE_ADDRESS=$(printf '%q' "$funder_ua")"
  fi

  # Resolve the TSS CA PEM from an operator
  local tss_ca_remote="$remote_secrets/tss-ca.pem"
  run_on_host "$RUNNER_PUBLIC_IP" \
    "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
     -i $remote_secrets/fleet-ssh-key $RUNNER_SSH_USER@${OPERATOR_PRIVATE_IPS[0]} \
     'cat /var/lib/intents-juno/operator-runtime/bundle/tls/ca.pem 2>/dev/null || \
      cat /home/$RUNNER_SSH_USER/operator-runtime/bundle/tls/ca.pem 2>/dev/null || \
      cat /var/lib/intents-juno/operator-runtime/tls/ca.pem 2>/dev/null || \
      cat /home/$RUNNER_SSH_USER/operator-runtime/tls/ca.pem 2>/dev/null || \
      cat /etc/intents-juno/tss-ca.pem 2>/dev/null || true' > $tss_ca_remote" || \
    warn "could not extract TSS CA PEM; withdraw-coordinator TLS may fail"

  # Build the remote run script
  local remote_run_script
  remote_run_script="$(cat <<REMOTESCRIPT
#!/usr/bin/env bash
set -euo pipefail
export PATH="\$HOME/.foundry/bin:\$PATH:/usr/local/go/bin:\$HOME/go/bin"
source "\$HOME/.cargo/env" 2>/dev/null || true

export JUNO_RPC_USER=$(printf '%q' "$juno_rpc_user")
export JUNO_RPC_PASS=$(printf '%q' "$juno_rpc_pass")
export AWS_REGION="$AWS_REGION"
$funder_env

# Kill any stale SSH tunnels from previous runs
for _pid in \$(pgrep -f 'ssh.*-N.*10\\.0\\.0' 2>/dev/null); do kill "\$_pid" 2>/dev/null; done
sleep 1

# Set up SSH tunnels to operators
TUNNEL_PIDS=()
cleanup_tunnels() {
  for pid in "\${TUNNEL_PIDS[@]}"; do
    kill "\$pid" 2>/dev/null || true
  done
}
trap cleanup_tunnels EXIT

$tunnel_setup_script

# Wait for tunnels
sleep 3

cd $remote_repo

# Forwarded args for run-testnet-e2e.sh
# Do NOT use exec — the EXIT trap must fire to clean up SSH tunnels,
# otherwise the SSH session hangs and the local orchestrator sees a
# non-zero exit code even though the test passed.
deploy/operators/dkg/e2e/run-testnet-e2e.sh run \\
  --workdir "$remote_workdir" \\
  --base-rpc-url "$BASE_RPC_URL" \\
  --base-chain-id "$BASE_CHAIN_ID" \\
  --base-funder-key-file "$remote_secrets/base-funder.key" \\
  --bridge-verifier-address "$BRIDGE_VERIFIER_ADDRESS" \\
  --bridge-deposit-image-id "$BRIDGE_DEPOSIT_IMAGE_ID" \\
  --bridge-withdraw-image-id "$BRIDGE_WITHDRAW_IMAGE_ID" \\
  --sp1-requestor-key-file "$remote_secrets/sp1-requestor.key" \\
  --sp1-deposit-program-url "$SP1_DEPOSIT_PROGRAM_URL" \\
  --sp1-withdraw-program-url "$SP1_WITHDRAW_PROGRAM_URL" \\
  --sp1-deposit-owallet-ivk-hex "$SP1_DEPOSIT_OWALLET_IVK_HEX" \\
  --sp1-withdraw-owallet-ovk-hex "$SP1_WITHDRAW_OWALLET_OVK_HEX" \\
  --sp1-witness-juno-scan-urls "$witness_scan_urls" \\
  --sp1-witness-juno-rpc-urls "$witness_rpc_urls" \\
  --sp1-witness-recipient-ua "$witness_recipient_ua" \\
  --sp1-witness-recipient-ufvk "$witness_ufvk" \\
  --sp1-input-s3-bucket "$DKG_S3_BUCKET" \\
  --shared-postgres-dsn "$SHARED_POSTGRES_DSN" \\
  --shared-kafka-brokers "$SHARED_KAFKA_BROKERS" \\
  --shared-ipfs-api-url "$SHARED_IPFS_API_URL" \\
  --shared-ecs-cluster-arn "$SHARED_ECS_CLUSTER_ARN" \\
  --shared-proof-requestor-service-name "$SHARED_PROOF_REQUESTOR_SERVICE" \\
  --shared-proof-funder-service-name "$SHARED_PROOF_FUNDER_SERVICE" \\
  --dkg-summary-path "$remote_dkg_summary" \\
  --operator-count "$OPERATOR_COUNT" \\
  --threshold "$OPERATOR_THRESHOLD" \\
  --withdraw-coordinator-tss-server-ca-file "$tss_ca_remote" \\
  --relayer-runtime-mode distributed \\
  --relayer-runtime-operator-hosts "$op_hosts_csv" \\
  --relayer-runtime-operator-ssh-user "$RUNNER_SSH_USER" \\
  --relayer-runtime-operator-ssh-key-file "$remote_secrets/fleet-ssh-key" \\
  --withdraw-blob-bucket "$DKG_S3_BUCKET" \\
  --withdraw-blob-prefix "withdraw-live" \\
  --backoffice-url "http://127.0.0.1:${BACKOFFICE_PORT}" \\
  --backoffice-auth-token "${BACKOFFICE_AUTH_TOKEN}" \\
  --output "$remote_workdir/reports/testnet-e2e-summary.json" \\
  $bridge_summary_flag \\
  ${EXTRA_E2E_FLAGS:-} \\
  --force
REMOTESCRIPT
  )"

  # Execute on runner (use base64 to avoid quoting issues)
  log "executing e2e test on runner (this takes 30-90 minutes)..."
  local exit_code=0
  local encoded_script
  encoded_script="$(printf '%s' "$remote_run_script" | base64)"
  ssh "${SSH_OPTS[@]}" "$RUNNER_SSH_USER@$RUNNER_PUBLIC_IP" \
    "echo '$encoded_script' | base64 -d | bash" \
    2>&1 | tee "$WORKDIR/logs/e2e-test.log" || exit_code=$?

  if [[ $exit_code -eq 0 ]]; then
    ok "E2E test PASSED"
  else
    warn "E2E test FAILED (exit code: $exit_code)"
  fi

  return "$exit_code"
}

# ── Artifact collection ──────────────────────────────────────────────────────

collect_artifacts() {
  step "Collecting artifacts from runner"

  local remote_workdir="/home/$RUNNER_SSH_USER/testnet-e2e-live"
  local artifacts_dir="$WORKDIR/artifacts"
  mkdir -p "$artifacts_dir"

  scp -r "${SSH_OPTS[@]}" -q \
    "$RUNNER_SSH_USER@$RUNNER_PUBLIC_IP:$remote_workdir/reports/" "$artifacts_dir/" 2>/dev/null || \
    warn "no reports to collect from runner"

  if [[ -f "$artifacts_dir/testnet-e2e-summary.json" ]]; then
    ok "Test summary: $artifacts_dir/testnet-e2e-summary.json"
    jq -r '.success // "unknown"' "$artifacts_dir/testnet-e2e-summary.json" || true
  fi
}

# ── Cleanup / teardown ───────────────────────────────────────────────────────

terraform_destroy() {
  local state_file="$WORKDIR/infra/terraform.tfstate"
  local tfvars_file="$WORKDIR/infra/terraform.tfvars.json"

  if [[ ! -f "$state_file" || ! -f "$tfvars_file" ]]; then
    log "no terraform state found; nothing to destroy"
    return 0
  fi

  step "Terraform destroy"
  tf_cmd -chdir="$TERRAFORM_DIR" init -input=false >/dev/null 2>&1
  tf_cmd -chdir="$TERRAFORM_DIR" destroy \
    -input=false -auto-approve \
    -state="$state_file" \
    -var-file="$tfvars_file" \
    2>&1 | tee "$WORKDIR/logs/terraform-destroy.log" || \
    warn "terraform destroy failed (manual cleanup may be needed)"

  ok "Terraform destroy completed"
}

delete_sp1_secret() {
  local arn="$1"
  [[ -n "$arn" ]] || return 0
  log "deleting SP1 Secrets Manager secret: $arn"
  env AWS_PROFILE="$AWS_PROFILE" aws secretsmanager delete-secret \
    --region "$AWS_REGION" \
    --secret-id "$arn" \
    --force-delete-without-recovery >/dev/null 2>&1 || \
    warn "failed to delete SP1 secret: $arn"
}

cleanup_trap() {
  local rc=$?
  if [[ "$CLEANUP_ENABLED" == "true" ]]; then
    terraform_destroy
    delete_sp1_secret "$CLEANUP_SP1_SECRET_ARN"
  else
    if [[ -n "$RUNNER_PUBLIC_IP" ]]; then
      log "infrastructure kept alive (--keep-infra). Runner: $RUNNER_SSH_USER@$RUNNER_PUBLIC_IP"
      log "to destroy: $0 cleanup --workdir $WORKDIR"
    fi
  fi
  if [[ $rc -ne 0 ]]; then
    log "logs: $WORKDIR/logs/"
  fi
  exit "$rc"
}

# ══════════════════════════════════════════════════════════════════════════════
# COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

cmd_run() {
  mkdir -p "$WORKDIR/logs" "$WORKDIR/reports" "$WORKDIR/local-secrets" "$WORKDIR/bin" "$CHECKPOINT_DIR"

  # Preflight
  for cmd in terraform aws ssh scp ssh-keygen jq curl gh go; do
    have_cmd "$cmd" || die "missing required command: $cmd"
  done

  # Validate AWS profile
  env AWS_PROFILE="$AWS_PROFILE" aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1 || \
    die "AWS profile '$AWS_PROFILE' not configured or credentials expired"
  ok "AWS profile '$AWS_PROFILE' valid"

  auto_discover_secrets
  resolve_gh_releases
  setup_ssh_keys

  # Register cleanup trap
  if [[ "$KEEP_INFRA" != "true" ]]; then
    CLEANUP_ENABLED=true
  fi
  trap cleanup_trap EXIT

  # Stage 1: Terraform
  if ! checkpoint_done "terraform"; then
    terraform_apply
    checkpoint_mark "terraform"
  fi
  read_tf_outputs

  # Load SP1 secret ARN for cleanup
  if [[ -f "$WORKDIR/local-secrets/sp1-secret-arn.txt" ]]; then
    CLEANUP_SP1_SECRET_ARN="$(cat "$WORKDIR/local-secrets/sp1-secret-arn.txt")"
  fi

  # Stage 2: Prepare hosts
  if ! checkpoint_done "prepare-hosts"; then
    prepare_runner_host
    prepare_operator_hosts
    extract_rpc_credentials
    checkpoint_mark "prepare-hosts"
  fi

  # Stage 3: DKG
  if ! checkpoint_done "dkg"; then
    run_distributed_dkg
    derive_owallet_keys
    checkpoint_mark "dkg"
  else
    # Load derived keys from DKG summary
    derive_owallet_keys
  fi

  # Stage 4: Stage secrets, provision operator config, and scale ECS
  if ! checkpoint_done "stage-secrets"; then
    stage_secrets_on_runner
    provision_operator_stack_config
    scale_proof_services 1
    checkpoint_mark "stage-secrets"
  fi

  # Stage 5: Deploy backoffice
  if ! checkpoint_done "backoffice"; then
    deploy_backoffice
    checkpoint_mark "backoffice"
  fi

  # Stage 6: Run test
  local test_exit=0
  run_e2e_test || test_exit=$?

  # Stage 6: Collect artifacts
  collect_artifacts

  # Print summary
  echo ""
  echo -e "${BOLD}═══════════════════════════════════════════${NC}"
  echo -e "${BOLD} E2E RUN COMPLETE${NC}"
  echo -e "${BOLD}═══════════════════════════════════════════${NC}"
  echo " Workdir:   $WORKDIR"
  echo " Logs:      $WORKDIR/logs/"
  echo " Artifacts: $WORKDIR/artifacts/"
  if [[ $test_exit -eq 0 ]]; then
    echo -e " Status:    ${GREEN}PASS${NC}"
  else
    echo -e " Status:    ${RED}FAIL${NC}"
  fi
  echo -e "${BOLD}═══════════════════════════════════════════${NC}"
  echo ""

  return "$test_exit"
}

cmd_resume() {
  mkdir -p "$WORKDIR/logs" "$WORKDIR/reports" "$CHECKPOINT_DIR"

  # Preflight
  for cmd in terraform aws ssh scp jq curl gh go; do
    have_cmd "$cmd" || die "missing required command: $cmd"
  done

  auto_discover_secrets
  resolve_gh_releases
  setup_ssh_keys

  # Register cleanup trap (keep infra by default on resume)
  KEEP_INFRA=true
  trap cleanup_trap EXIT

  # Read existing terraform state
  read_tf_outputs

  # Apply any terraform changes (e.g. new SG rules) that were added since last full run
  log "applying terraform to ensure infrastructure is current..."
  terraform_apply
  read_tf_outputs   # re-read in case apply created new outputs

  if [[ -f "$WORKDIR/local-secrets/sp1-secret-arn.txt" ]]; then
    CLEANUP_SP1_SECRET_ARN="$(cat "$WORKDIR/local-secrets/sp1-secret-arn.txt")"
  fi

  # Update runner code to current local commit (test scripts may have changed)
  local _current_commit
  _current_commit="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "main")"
  log "updating runner code to $_current_commit..."
  run_on_host "$RUNNER_PUBLIC_IP" \
    "cd \$HOME/intents-juno && git fetch origin --prune && git checkout $_current_commit 2>/dev/null || git checkout origin/main"
  ok "runner code updated"

  # Ensure DKG is done
  [[ -f "$WORKDIR/reports/dkg-summary.json" ]] || \
    die "no DKG summary found; run 'run' first"

  # Derive keys (needed for test args)
  derive_owallet_keys

  # Re-stage secrets and operator config (in case runner was restarted)
  stage_secrets_on_runner
  provision_operator_stack_config

  # Restart tss-host on all operators to clear stale signing state from prior runs
  log "restarting tss-host.service on all operators..."
  for op_ip in "${OPERATOR_PUBLIC_IPS[@]}"; do
    ssh "${SSH_OPTS[@]}" "$RUNNER_SSH_USER@$op_ip" \
      'sudo systemctl restart tss-host.service' || \
      warn "failed to restart tss-host on $op_ip"
  done
  ok "tss-host restarted on all operators"

  scale_proof_services 1

  # Deploy backoffice
  deploy_backoffice

  # Run test
  local test_exit=0
  run_e2e_test || test_exit=$?
  collect_artifacts

  echo ""
  if [[ $test_exit -eq 0 ]]; then
    echo -e "${GREEN}E2E RESUME: PASS${NC}"
  else
    echo -e "${RED}E2E RESUME: FAIL${NC}"
  fi
  echo ""

  return "$test_exit"
}

cmd_cleanup() {
  mkdir -p "$WORKDIR/logs" 2>/dev/null || true

  for cmd in terraform aws; do
    have_cmd "$cmd" || die "missing required command: $cmd"
  done

  terraform_destroy

  if [[ -f "$WORKDIR/local-secrets/sp1-secret-arn.txt" ]]; then
    delete_sp1_secret "$(cat "$WORKDIR/local-secrets/sp1-secret-arn.txt")"
  fi

  ok "Cleanup complete"
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

parse_args "$@"

log "e2e-local: command=$COMMAND workdir=$WORKDIR aws-profile=$AWS_PROFILE region=$AWS_REGION"

case "$COMMAND" in
  run)     cmd_run ;;
  resume)  cmd_resume ;;
  cleanup) cmd_cleanup ;;
esac
