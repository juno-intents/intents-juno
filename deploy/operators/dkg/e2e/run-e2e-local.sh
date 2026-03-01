#!/usr/bin/env bash
# shellcheck shell=bash
#
# Checkpoint-based local e2e runner against AWS infrastructure.
#
# Usage:
#   ./run-e2e-local.sh --config <env-file> [--stage <stage-name>] [--reset]
#
# Stages execute sequentially and write checkpoint files. On re-run, completed
# stages are skipped automatically. Use --stage to resume from a specific stage.
# Use --reset to clear all checkpoints and start fresh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
AWS_PROFILE="${AWS_PROFILE:-juno}"
WORKDIR="${WORKDIR:-$REPO_ROOT/tmp/e2e-local}"
CHECKPOINT_DIR="$WORKDIR/.checkpoints"
LOG_DIR="$WORKDIR/logs"
REPORT_DIR="$WORKDIR/reports"
PID_DIR="$WORKDIR/pids"

# ── Colours and logging ──────────────────────────────────────────────────────

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[$(date +%H:%M:%S)]${NC} $*"; }
ok()   { echo -e "${GREEN}[$(date +%H:%M:%S)] ✓${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] !${NC} $*" >&2; }
die()  { echo -e "${RED}[$(date +%H:%M:%S)] FATAL:${NC} $*" >&2; exit 1; }

# ── Checkpoint helpers ────────────────────────────────────────────────────────

checkpoint_done() {
  [[ -f "$CHECKPOINT_DIR/$1.done" ]]
}

checkpoint_mark() {
  mkdir -p "$CHECKPOINT_DIR"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$CHECKPOINT_DIR/$1.done"
  ok "Stage '$1' completed"
}

checkpoint_reset() {
  rm -rf "$CHECKPOINT_DIR"
  log "All checkpoints cleared"
}

# ── Process management ────────────────────────────────────────────────────────

start_bg() {
  local name="$1"; shift
  local logfile="$LOG_DIR/$name.log"
  mkdir -p "$PID_DIR" "$LOG_DIR"

  log "Starting $name ..."
  "$@" > "$logfile" 2>&1 &
  local pid=$!
  echo "$pid" > "$PID_DIR/$name.pid"
  echo "$name" >> "$PID_DIR/.all"
  log "  $name started (pid=$pid, log=$logfile)"
}

stop_all_bg() {
  [[ -f "$PID_DIR/.all" ]] || return 0
  log "Stopping background services ..."
  while read -r name; do
    local pidfile="$PID_DIR/$name.pid"
    if [[ -f "$pidfile" ]]; then
      local pid; pid=$(cat "$pidfile")
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
        log "  Stopped $name (pid=$pid)"
      fi
    fi
  done < "$PID_DIR/.all"
  rm -f "$PID_DIR/.all"
}

is_running() {
  local pidfile="$PID_DIR/$1.pid"
  [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null
}

# ── Canary / health checks ───────────────────────────────────────────────────

wait_for_http() {
  local label="$1" url="$2" timeout="${3:-60}"
  local deadline; deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    if curl -sf -o /dev/null "$url" 2>/dev/null; then
      ok "$label is healthy ($url)"
      return 0
    fi
    sleep 2
  done
  die "$label did not become healthy within ${timeout}s ($url)"
}

wait_for_postgres() {
  local dsn="$1" timeout="${2:-30}"
  local deadline; deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    if psql "$dsn" -c "SELECT 1" >/dev/null 2>&1; then
      ok "Postgres reachable"
      return 0
    fi
    sleep 2
  done
  die "Postgres unreachable within ${timeout}s"
}

# ── Usage ─────────────────────────────────────────────────────────────────────

usage() {
  cat <<'USAGE'
Usage: run-e2e-local.sh --config <env-file> [options]

Options:
  --config <file>    Required. Env file with all configuration variables.
  --stage <name>     Resume from this specific stage (skips earlier completed stages).
  --reset            Clear all checkpoints and start fresh.
  --skip-infra       Skip infrastructure validation (assume already running).
  --skip-services    Skip service startup (assume already running).
  --dry-run          Print what would happen without executing.

Stages (in order):
  01-validate-config       Validate all required config variables
  02-build-binaries        Build Go binaries
  03-check-aws-infra       Validate Postgres, Kafka, IPFS, ECS connectivity
  04-check-operators       Verify operator checkpoint services are running
  05-deploy-contracts      Deploy Bridge/wJUNO/FeeDistributor (or verify existing)
  06-start-bridge-api      Start bridge-api service
  07-start-base-relayer    Start base-relayer service
  08-start-deposit-relayer Start deposit-relayer service
  09-start-withdraw-coord  Start withdraw-coordinator service
  10-start-withdraw-final  Start withdraw-finalizer service
  11-canary-health         Canary: all services healthy, checkpoint flowing
  12-run-orchestrator      Run e2e-orchestrator (deposit + withdrawal flow)
  13-collect-results       Collect logs, report, cleanup

Config file variables (source'd as bash):
  # AWS
  AWS_REGION=us-east-1

  # Endpoints
  BASE_RPC_URL=https://sepolia.base.org
  BASE_CHAIN_ID=84532
  JUNO_RPC_URL=http://...
  JUNO_RPC_USER=...
  JUNO_RPC_PASS=...

  # Shared infrastructure
  SHARED_POSTGRES_DSN="postgresql://..."
  SHARED_KAFKA_BROKERS="b1:9094,b2:9094"
  SHARED_IPFS_API_URL="http://..."
  SHARED_TOPIC_PREFIX="shared.infra.e2e"

  # Contracts (leave empty to deploy fresh)
  BRIDGE_ADDRESS=
  WJUNO_ADDRESS=
  FEE_DISTRIBUTOR_ADDRESS=
  OPERATOR_REGISTRY_ADDRESS=

  # Bridge deploy params (if deploying fresh)
  BASE_FUNDER_KEY_FILE=./base-funder.key
  BRIDGE_VERIFIER_ADDRESS=0x397A...
  BRIDGE_DEPOSIT_IMAGE_ID=0x...
  BRIDGE_WITHDRAW_IMAGE_ID=0x...
  BRIDGE_FEE_BPS=50
  BRIDGE_RELAYER_TIP_BPS=1000
  BRIDGE_REFUND_WINDOW=86400
  BRIDGE_MAX_EXPIRY_EXT=604800

  # Operators
  OPERATOR_ADDRESSES="0x1,0x2,0x3,0x4,0x5"
  OPERATOR_THRESHOLD=3

  # e2e-orchestrator params
  RECIPIENT_ADDRESS=0x...
  JUNO_FUNDER_SOURCE_ADDRESS=...
  OWALLET_UA=...
  JUNO_WALLET_ID=...
  DEPOSIT_AMOUNT_ZAT=100000
  WITHDRAW_AMOUNT=10000
  WITHDRAW_RECIPIENT_RAW_HEX=...

  # Witness extraction
  JUNO_SCAN_URL=https://...
  JUNO_SCAN_BEARER_TOKEN=...
  WITNESS_EXTRACT_BIN=juno-witness-extract

  # SP1
  SP1_REQUESTOR_KEY_FILE=./sp1.key

  # Service ports (local)
  BRIDGE_API_LISTEN=127.0.0.1:8082
  BASE_RELAYER_LISTEN=127.0.0.1:8080

  # TSS (for withdraw-coordinator)
  TSS_URL=https://...
  TSS_SERVER_CA_FILE=./tss-ca.pem

  # Blobs
  BLOB_S3_BUCKET=...
  BLOB_S3_PREFIX=withdraw-live
USAGE
  exit 1
}

# ── Parse arguments ───────────────────────────────────────────────────────────

CONFIG_FILE=""
RESUME_STAGE=""
SKIP_INFRA=false
SKIP_SERVICES=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)   CONFIG_FILE="$2"; shift 2 ;;
    --stage)    RESUME_STAGE="$2"; shift 2 ;;
    --reset)    checkpoint_reset; shift ;;
    --skip-infra)    SKIP_INFRA=true; shift ;;
    --skip-services) SKIP_SERVICES=true; shift ;;
    --dry-run)       DRY_RUN=true; shift ;;
    -h|--help)  usage ;;
    *)          die "Unknown argument: $1" ;;
  esac
done

[[ -n "$CONFIG_FILE" ]] || { warn "Missing --config <file>"; usage; }
[[ -f "$CONFIG_FILE" ]] || die "Config file not found: $CONFIG_FILE"

# shellcheck source=/dev/null
source "$CONFIG_FILE"

mkdir -p "$WORKDIR" "$CHECKPOINT_DIR" "$LOG_DIR" "$REPORT_DIR" "$PID_DIR"

# Cleanup on exit.
trap 'stop_all_bg; log "Done. Logs in $LOG_DIR, reports in $REPORT_DIR"' EXIT

# ── Stage runner ──────────────────────────────────────────────────────────────

STAGE_ORDER=(
  01-validate-config
  02-build-binaries
  03-check-aws-infra
  04-check-operators
  05-deploy-contracts
  06-start-bridge-api
  07-start-base-relayer
  08-start-deposit-relayer
  09-start-withdraw-coord
  10-start-withdraw-final
  11-canary-health
  12-run-orchestrator
  13-collect-results
)

should_run_stage() {
  local stage="$1"
  if checkpoint_done "$stage"; then
    log "Stage '$stage' already done — skipping"
    return 1
  fi
  if [[ -n "$RESUME_STAGE" ]]; then
    # Skip stages before the resume target.
    local found=false
    for s in "${STAGE_ORDER[@]}"; do
      if [[ "$s" == "$RESUME_STAGE" ]]; then found=true; fi
      if [[ "$s" == "$stage" ]]; then
        $found && return 0 || return 1
      fi
    done
  fi
  return 0
}

run_stage() {
  local stage="$1"
  if ! should_run_stage "$stage"; then return 0; fi
  log "━━━ Stage: $stage ━━━"
  if $DRY_RUN; then
    log "  [dry-run] would execute stage_${stage//-/_}"
    return 0
  fi
  "stage_${stage//-/_}"
  checkpoint_mark "$stage"
}

# ══════════════════════════════════════════════════════════════════════════════
# STAGE IMPLEMENTATIONS
# ══════════════════════════════════════════════════════════════════════════════

stage_01_validate_config() {
  local required_vars=(
    BASE_RPC_URL BASE_CHAIN_ID JUNO_RPC_URL JUNO_RPC_USER JUNO_RPC_PASS
    SHARED_POSTGRES_DSN SHARED_KAFKA_BROKERS
    RECIPIENT_ADDRESS JUNO_FUNDER_SOURCE_ADDRESS OWALLET_UA JUNO_WALLET_ID
    DEPOSIT_AMOUNT_ZAT WITHDRAW_AMOUNT WITHDRAW_RECIPIENT_RAW_HEX
    JUNO_SCAN_URL OPERATOR_ADDRESSES OPERATOR_THRESHOLD
    BASE_RELAYER_LISTEN BRIDGE_API_LISTEN
  )
  local missing=()
  for var in "${required_vars[@]}"; do
    if [[ -z "${!var:-}" ]]; then
      missing+=("$var")
    fi
  done
  if (( ${#missing[@]} > 0 )); then
    die "Missing required config variables: ${missing[*]}"
  fi

  # Validate AWS profile.
  if ! aws sts get-caller-identity --profile "$AWS_PROFILE" >/dev/null 2>&1; then
    die "AWS profile '$AWS_PROFILE' is not configured or credentials expired"
  fi
  ok "AWS profile '$AWS_PROFILE' valid ($(aws sts get-caller-identity --profile "$AWS_PROFILE" --query Account --output text))"

  # Check binaries exist in PATH.
  for bin in psql curl jq forge go; do
    command -v "$bin" >/dev/null || die "Required binary not in PATH: $bin"
  done
  ok "All required config variables and tools present"
}

stage_02_build_binaries() {
  log "Building Go binaries..."
  cd "$REPO_ROOT"

  local bins=(
    bridge-api base-relayer deposit-relayer withdraw-coordinator
    withdraw-finalizer e2e-orchestrator shared-infra-e2e
  )
  for b in "${bins[@]}"; do
    log "  Building cmd/$b ..."
    go build -o "$WORKDIR/bin/$b" "./cmd/$b/"
  done
  ok "All binaries built to $WORKDIR/bin/"

  # Build Solidity contracts if we need to deploy.
  if [[ -z "${BRIDGE_ADDRESS:-}" ]]; then
    log "  Building Solidity contracts..."
    (cd "$REPO_ROOT/contracts" && forge build --silent)
    ok "Solidity contracts compiled"
  fi
}

stage_03_check_aws_infra() {
  if $SKIP_INFRA; then
    warn "Skipping infrastructure checks (--skip-infra)"
    return 0
  fi

  log "Checking Postgres connectivity..."
  wait_for_postgres "$SHARED_POSTGRES_DSN" 15

  log "Checking Kafka brokers..."
  local first_broker; first_broker="${SHARED_KAFKA_BROKERS%%,*}"
  local broker_host="${first_broker%%:*}"
  local broker_port="${first_broker##*:}"
  if timeout 5 bash -c "echo >/dev/tcp/$broker_host/$broker_port" 2>/dev/null; then
    ok "Kafka broker reachable ($first_broker)"
  else
    die "Kafka broker unreachable: $first_broker"
  fi

  if [[ -n "${SHARED_IPFS_API_URL:-}" ]]; then
    log "Checking IPFS..."
    if curl -sf -o /dev/null "${SHARED_IPFS_API_URL}/api/v0/id" 2>/dev/null; then
      ok "IPFS reachable"
    else
      warn "IPFS not reachable (non-fatal, checkpoints may fail)"
    fi
  fi

  # Check ECS proof services if configured.
  if [[ -n "${SHARED_ECS_CLUSTER_ARN:-}" ]]; then
    log "Checking ECS proof services..."
    local region="${AWS_REGION:-us-east-1}"
    for svc in "${SHARED_PROOF_REQUESTOR_SERVICE:-}" "${SHARED_PROOF_FUNDER_SERVICE:-}"; do
      [[ -n "$svc" ]] || continue
      local running; running=$(
        aws ecs describe-services --profile "$AWS_PROFILE" --region "$region" \
          --cluster "$SHARED_ECS_CLUSTER_ARN" --services "$svc" \
          --query 'services[0].runningCount' --output text 2>/dev/null
      )
      if [[ "$running" -gt 0 ]] 2>/dev/null; then
        ok "ECS $svc: $running running"
      else
        warn "ECS $svc: not running (running=$running)"
      fi
    done
  fi

  ok "AWS infrastructure checks passed"
}

stage_04_check_operators() {
  log "Checking operator checkpoint flow..."

  # Verify at least one recent checkpoint exists in Postgres.
  local ckpt_count
  ckpt_count=$(psql "$SHARED_POSTGRES_DSN" -Atqc \
    "SELECT COUNT(*) FROM checkpoint_packages WHERE persisted_at > now() - interval '30 minutes'" 2>/dev/null || echo "0")

  if (( ckpt_count > 0 )); then
    ok "Found $ckpt_count recent checkpoint packages (last 30m)"
  else
    warn "No recent checkpoints found. Operators may not be running."
    log "Checking if checkpoint_packages table exists..."
    local table_exists
    table_exists=$(psql "$SHARED_POSTGRES_DSN" -Atqc \
      "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='checkpoint_packages'" 2>/dev/null || echo "0")
    if (( table_exists == 0 )); then
      die "checkpoint_packages table does not exist. Operators have never run."
    fi
    local total_ckpts
    total_ckpts=$(psql "$SHARED_POSTGRES_DSN" -Atqc "SELECT COUNT(*) FROM checkpoint_packages" 2>/dev/null || echo "0")
    warn "Total checkpoints ever: $total_ckpts (none recent — operators may be stopped)"
    log "Continuing anyway — the deposit-relayer will wait for fresh checkpoints."
  fi
}

stage_05_deploy_contracts() {
  if [[ -n "${BRIDGE_ADDRESS:-}" && -n "${WJUNO_ADDRESS:-}" && -n "${FEE_DISTRIBUTOR_ADDRESS:-}" ]]; then
    ok "Using existing contracts: Bridge=$BRIDGE_ADDRESS wJUNO=$WJUNO_ADDRESS FeeDistributor=$FEE_DISTRIBUTOR_ADDRESS"
    return 0
  fi

  log "Deploying fresh bridge contracts to Base..."

  # Ensure required deploy vars exist.
  [[ -n "${BASE_FUNDER_KEY_FILE:-}" ]] || die "BASE_FUNDER_KEY_FILE required for fresh deploy"
  [[ -f "$BASE_FUNDER_KEY_FILE" ]] || die "BASE_FUNDER_KEY_FILE not found: $BASE_FUNDER_KEY_FILE"
  [[ -n "${BRIDGE_VERIFIER_ADDRESS:-}" ]] || die "BRIDGE_VERIFIER_ADDRESS required"
  [[ -n "${BRIDGE_DEPOSIT_IMAGE_ID:-}" ]] || die "BRIDGE_DEPOSIT_IMAGE_ID required"
  [[ -n "${BRIDGE_WITHDRAW_IMAGE_ID:-}" ]] || die "BRIDGE_WITHDRAW_IMAGE_ID required"

  local deploy_output="$REPORT_DIR/bridge-deploy-summary.json"

  "$WORKDIR/bin/bridge-e2e" \
    --deploy-only \
    --base-rpc-url "$BASE_RPC_URL" \
    --base-chain-id "$BASE_CHAIN_ID" \
    --private-key-file "$BASE_FUNDER_KEY_FILE" \
    --verifier-address "$BRIDGE_VERIFIER_ADDRESS" \
    --deposit-image-id "$BRIDGE_DEPOSIT_IMAGE_ID" \
    --withdraw-image-id "$BRIDGE_WITHDRAW_IMAGE_ID" \
    --fee-bps "${BRIDGE_FEE_BPS:-50}" \
    --relayer-tip-bps "${BRIDGE_RELAYER_TIP_BPS:-1000}" \
    --refund-window "${BRIDGE_REFUND_WINDOW:-86400}" \
    --max-expiry-extension "${BRIDGE_MAX_EXPIRY_EXT:-604800}" \
    --operator-addresses "$OPERATOR_ADDRESSES" \
    --operator-threshold "$OPERATOR_THRESHOLD" \
    --contracts-out "$REPO_ROOT/contracts/out" \
    --output "$deploy_output" \
    2>&1 | tee "$LOG_DIR/bridge-deploy.log"

  # Parse deployed addresses from summary.
  BRIDGE_ADDRESS=$(jq -r '.contracts.bridge' "$deploy_output")
  WJUNO_ADDRESS=$(jq -r '.contracts.wjuno' "$deploy_output")
  FEE_DISTRIBUTOR_ADDRESS=$(jq -r '.contracts.fee_distributor' "$deploy_output")
  OPERATOR_REGISTRY_ADDRESS=$(jq -r '.contracts.operator_registry // empty' "$deploy_output")

  ok "Contracts deployed: Bridge=$BRIDGE_ADDRESS wJUNO=$WJUNO_ADDRESS FeeDistributor=$FEE_DISTRIBUTOR_ADDRESS"

  # Persist so checkpoint resume can load them.
  cat > "$CHECKPOINT_DIR/contracts.env" <<ENVEOF
BRIDGE_ADDRESS=$BRIDGE_ADDRESS
WJUNO_ADDRESS=$WJUNO_ADDRESS
FEE_DISTRIBUTOR_ADDRESS=$FEE_DISTRIBUTOR_ADDRESS
OPERATOR_REGISTRY_ADDRESS=${OPERATOR_REGISTRY_ADDRESS:-}
ENVEOF
}

# Load contract addresses from checkpoint if re-running after stage 5.
_load_contract_checkpoint() {
  if [[ -f "$CHECKPOINT_DIR/contracts.env" ]]; then
    # shellcheck source=/dev/null
    source "$CHECKPOINT_DIR/contracts.env"
  fi
}

stage_06_start_bridge_api() {
  _load_contract_checkpoint
  if $SKIP_SERVICES; then warn "Skipping bridge-api start (--skip-services)"; return 0; fi
  if is_running bridge-api; then ok "bridge-api already running"; return 0; fi

  export JUNO_QUEUE_KAFKA_TLS=true
  start_bg bridge-api \
    "$WORKDIR/bin/bridge-api" \
      --listen "$BRIDGE_API_LISTEN" \
      --postgres-dsn "$SHARED_POSTGRES_DSN" \
      --base-chain-id "$BASE_CHAIN_ID" \
      --bridge-address "$BRIDGE_ADDRESS" \
      --owallet-ua "$OWALLET_UA" \
      --queue-driver kafka \
      --queue-brokers "$SHARED_KAFKA_BROKERS" \
      --deposit-event-topic "${SHARED_TOPIC_PREFIX:-shared.infra.e2e}.deposits.events" \
      --withdraw-request-topic "${SHARED_TOPIC_PREFIX:-shared.infra.e2e}.withdrawals.requested"

  wait_for_http "bridge-api" "http://$BRIDGE_API_LISTEN/healthz" 30
}

stage_07_start_base_relayer() {
  if $SKIP_SERVICES; then warn "Skipping base-relayer start (--skip-services)"; return 0; fi
  if is_running base-relayer; then ok "base-relayer already running"; return 0; fi

  [[ -n "${BASE_RELAYER_PRIVATE_KEYS:-}" ]] || die "BASE_RELAYER_PRIVATE_KEYS env var required"
  [[ -n "${BASE_RELAYER_AUTH_TOKEN:-}" ]] || die "BASE_RELAYER_AUTH_TOKEN env var required"

  start_bg base-relayer \
    "$WORKDIR/bin/base-relayer" \
      --rpc-url "$BASE_RPC_URL" \
      --chain-id "$BASE_CHAIN_ID" \
      --listen "$BASE_RELAYER_LISTEN"

  wait_for_http "base-relayer" "http://$BASE_RELAYER_LISTEN/healthz" 30
}

stage_08_start_deposit_relayer() {
  _load_contract_checkpoint
  if $SKIP_SERVICES; then warn "Skipping deposit-relayer start (--skip-services)"; return 0; fi
  if is_running deposit-relayer; then ok "deposit-relayer already running"; return 0; fi

  local oper_list; oper_list="${OPERATOR_ADDRESSES//,/ }"
  local base_relayer_url="http://$BASE_RELAYER_LISTEN"

  export JUNO_QUEUE_KAFKA_TLS=true
  export BASE_RELAYER_AUTH_TOKEN="${BASE_RELAYER_AUTH_TOKEN:-}"

  start_bg deposit-relayer \
    "$WORKDIR/bin/deposit-relayer" \
      --postgres-dsn "$SHARED_POSTGRES_DSN" \
      --base-chain-id "$BASE_CHAIN_ID" \
      --bridge-address "$BRIDGE_ADDRESS" \
      --operators "$OPERATOR_ADDRESSES" \
      --operator-threshold "$OPERATOR_THRESHOLD" \
      --deposit-image-id "${BRIDGE_DEPOSIT_IMAGE_ID:-}" \
      --base-relayer-url "$base_relayer_url" \
      --queue-driver kafka \
      --queue-brokers "$SHARED_KAFKA_BROKERS" \
      --queue-topics "${SHARED_TOPIC_PREFIX:-shared.infra.e2e}.deposits.events,${SHARED_TOPIC_PREFIX:-shared.infra.e2e}.checkpoints.packages" \
      --proof-driver queue \
      --proof-request-topic "${SHARED_TOPIC_PREFIX:-shared.infra.e2e}.proof.requests" \
      --max-items "${DEPOSIT_MAX_ITEMS:-1}" \
      --max-age "${DEPOSIT_MAX_AGE:-30s}"
}

stage_09_start_withdraw_coord() {
  _load_contract_checkpoint
  if $SKIP_SERVICES; then warn "Skipping withdraw-coordinator start (--skip-services)"; return 0; fi
  if is_running withdraw-coordinator; then ok "withdraw-coordinator already running"; return 0; fi

  [[ -n "${TSS_URL:-}" ]] || die "TSS_URL required for withdraw-coordinator"

  export JUNO_QUEUE_KAFKA_TLS=true

  local tss_ca_args=()
  if [[ -n "${TSS_SERVER_CA_FILE:-}" ]]; then
    tss_ca_args=(--tss-server-ca-file "$TSS_SERVER_CA_FILE")
  fi

  start_bg withdraw-coordinator \
    "$WORKDIR/bin/withdraw-coordinator" \
      --postgres-dsn "$SHARED_POSTGRES_DSN" \
      --base-chain-id "$BASE_CHAIN_ID" \
      --bridge-address "$BRIDGE_ADDRESS" \
      --queue-driver kafka \
      --queue-brokers "$SHARED_KAFKA_BROKERS" \
      --queue-topics "${SHARED_TOPIC_PREFIX:-shared.infra.e2e}.withdrawals.requested" \
      --juno-rpc-url "$JUNO_RPC_URL" \
      --tss-url "$TSS_URL" \
      "${tss_ca_args[@]}" \
      --blob-driver s3 \
      --blob-bucket "${BLOB_S3_BUCKET:-}" \
      --blob-prefix "${BLOB_S3_PREFIX:-withdraw-live}" \
      --max-items "${WITHDRAW_MAX_ITEMS:-1}" \
      --max-age "${WITHDRAW_MAX_AGE:-30s}"
}

stage_10_start_withdraw_final() {
  _load_contract_checkpoint
  if $SKIP_SERVICES; then warn "Skipping withdraw-finalizer start (--skip-services)"; return 0; fi
  if is_running withdraw-finalizer; then ok "withdraw-finalizer already running"; return 0; fi

  local base_relayer_url="http://$BASE_RELAYER_LISTEN"

  export JUNO_QUEUE_KAFKA_TLS=true
  export BASE_RELAYER_AUTH_TOKEN="${BASE_RELAYER_AUTH_TOKEN:-}"

  start_bg withdraw-finalizer \
    "$WORKDIR/bin/withdraw-finalizer" \
      --postgres-dsn "$SHARED_POSTGRES_DSN" \
      --base-chain-id "$BASE_CHAIN_ID" \
      --bridge-address "$BRIDGE_ADDRESS" \
      --operators "$OPERATOR_ADDRESSES" \
      --operator-threshold "$OPERATOR_THRESHOLD" \
      --withdraw-image-id "${BRIDGE_WITHDRAW_IMAGE_ID:-}" \
      --base-relayer-url "$base_relayer_url" \
      --queue-driver kafka \
      --queue-brokers "$SHARED_KAFKA_BROKERS" \
      --queue-topics "${SHARED_TOPIC_PREFIX:-shared.infra.e2e}.checkpoints.packages" \
      --proof-driver queue \
      --proof-request-topic "${SHARED_TOPIC_PREFIX:-shared.infra.e2e}.proof.requests"
}

stage_11_canary_health() {
  log "Running canary health checks..."

  # Check bridge-api.
  if ! $SKIP_SERVICES; then
    wait_for_http "bridge-api" "http://$BRIDGE_API_LISTEN/healthz" 10
    wait_for_http "base-relayer" "http://$BASE_RELAYER_LISTEN/healthz" 10
  fi

  # Verify bridge-api returns config.
  local config_resp
  config_resp=$(curl -sf "http://$BRIDGE_API_LISTEN/v1/config" 2>/dev/null || echo "{}")
  local api_bridge; api_bridge=$(echo "$config_resp" | jq -r '.bridgeAddress // empty')
  if [[ -n "$api_bridge" ]]; then
    ok "bridge-api config OK (bridge=$api_bridge)"
  else
    warn "bridge-api /v1/config returned unexpected response"
  fi

  # Check that background processes haven't crashed.
  local crashed=false
  for svc in bridge-api base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer; do
    if [[ -f "$PID_DIR/$svc.pid" ]] && ! is_running "$svc"; then
      warn "$svc has crashed! Check $LOG_DIR/$svc.log"
      tail -20 "$LOG_DIR/$svc.log" 2>/dev/null || true
      crashed=true
    fi
  done
  if $crashed; then
    die "One or more services crashed during canary check"
  fi

  ok "All canary health checks passed"
}

stage_12_run_orchestrator() {
  _load_contract_checkpoint
  log "Running e2e-orchestrator..."

  local bridge_api_url="http://$BRIDGE_API_LISTEN"
  local orchestrator_report="$REPORT_DIR/e2e-orchestrator-report.json"

  export JUNO_RPC_USER JUNO_RPC_PASS
  export JUNO_SCAN_BEARER_TOKEN="${JUNO_SCAN_BEARER_TOKEN:-}"

  "$WORKDIR/bin/e2e-orchestrator" \
    --bridge-api-url "$bridge_api_url" \
    --base-rpc-url "$BASE_RPC_URL" \
    --base-chain-id "$BASE_CHAIN_ID" \
    --juno-rpc-url "$JUNO_RPC_URL" \
    --bridge-address "$BRIDGE_ADDRESS" \
    --wjuno-address "$WJUNO_ADDRESS" \
    --fee-distributor-address "$FEE_DISTRIBUTOR_ADDRESS" \
    --recipient-address "$RECIPIENT_ADDRESS" \
    --juno-funder-source-address "$JUNO_FUNDER_SOURCE_ADDRESS" \
    --owallet-ua "$OWALLET_UA" \
    --juno-wallet-id "$JUNO_WALLET_ID" \
    --deposit-amount-zat "$DEPOSIT_AMOUNT_ZAT" \
    --withdraw-amount "$WITHDRAW_AMOUNT" \
    --withdraw-recipient-raw-hex "$WITHDRAW_RECIPIENT_RAW_HEX" \
    --juno-scan-url "$JUNO_SCAN_URL" \
    --witness-extract-bin "${WITNESS_EXTRACT_BIN:-juno-witness-extract}" \
    --run-timeout "${E2E_RUN_TIMEOUT:-45m}" \
    --deposit-timeout "${E2E_DEPOSIT_TIMEOUT:-20m}" \
    --withdraw-timeout "${E2E_WITHDRAW_TIMEOUT:-30m}" \
    --poll-interval "${E2E_POLL_INTERVAL:-5s}" \
    --expected-fee-bps "${BRIDGE_FEE_BPS:-50}" \
    --expected-tip-bps "${BRIDGE_RELAYER_TIP_BPS:-1000}" \
    ${SHARED_IPFS_API_URL:+--ipfs-api-url "$SHARED_IPFS_API_URL"} \
    --output "$orchestrator_report" \
    2>&1 | tee "$LOG_DIR/e2e-orchestrator.log"

  local exit_code=${PIPESTATUS[0]}

  if [[ -f "$orchestrator_report" ]]; then
    local success; success=$(jq -r '.success' "$orchestrator_report" 2>/dev/null || echo "false")
    if [[ "$success" == "true" ]]; then
      ok "E2E orchestrator PASSED"
    else
      warn "E2E orchestrator FAILED (report: $orchestrator_report)"
      jq -r '.deposit // empty, .withdrawal // empty' "$orchestrator_report" 2>/dev/null || true
    fi
  fi

  return "$exit_code"
}

stage_13_collect_results() {
  log "Collecting results..."

  # Copy orchestrator report to top-level.
  if [[ -f "$REPORT_DIR/e2e-orchestrator-report.json" ]]; then
    cp "$REPORT_DIR/e2e-orchestrator-report.json" "$WORKDIR/e2e-result.json"
    ok "Result: $WORKDIR/e2e-result.json"
  fi

  # Snapshot service logs.
  for svc in bridge-api base-relayer deposit-relayer withdraw-coordinator withdraw-finalizer; do
    if [[ -f "$LOG_DIR/$svc.log" ]]; then
      local lines; lines=$(wc -l < "$LOG_DIR/$svc.log")
      log "  $svc.log: $lines lines"
    fi
  done

  # Print summary.
  echo ""
  echo "═══════════════════════════════════════════"
  echo " E2E RUN COMPLETE"
  echo "═══════════════════════════════════════════"
  echo " Workdir:  $WORKDIR"
  echo " Logs:     $LOG_DIR/"
  echo " Reports:  $REPORT_DIR/"
  echo " Result:   $WORKDIR/e2e-result.json"
  echo "═══════════════════════════════════════════"

  if [[ -f "$WORKDIR/e2e-result.json" ]]; then
    local success; success=$(jq -r '.success' "$WORKDIR/e2e-result.json" 2>/dev/null || echo "unknown")
    if [[ "$success" == "true" ]]; then
      echo -e " Status:   ${GREEN}PASS${NC}"
    else
      echo -e " Status:   ${RED}FAIL${NC}"
    fi
  fi
  echo ""
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

log "E2E local runner — workdir=$WORKDIR"
log "Checkpoint dir: $CHECKPOINT_DIR"

for stage in "${STAGE_ORDER[@]}"; do
  run_stage "$stage"
done

log "All stages complete."
