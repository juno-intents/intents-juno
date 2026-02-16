#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"
prepare_script_runtime "$SCRIPT_DIR"

usage() {
  cat <<'EOF'
Usage:
  run-dkg-backup-restore.sh run [options]

Options:
  --workdir <path>            working directory (default: <repo>/tmp/testnet-e2e/dkg)
  --operator-count <n>        number of operators (default: 5)
  --threshold <n>             quorum threshold (default: 3)
  --network <name>            DKG network value (default: testnet)
  --base-port <port>          first operator grpc port (default: 18443)
  --release-tag <tag>         DKG tool release tag (default: v0.1.0)
  --output <path>             summary json output (default: <workdir>/reports/dkg-summary.json)
  --force                     remove existing workdir before starting
  --leave-running             leave restored operators running at the end

This script executes:
  1) 5-operator DKG ceremony
  2) per-operator age backup export + dkg-backup.zip package
  3) runtime deletion (backup-only state)
  4) restore from dkg-backup.zip
  5) operator boot/status verification
EOF
}

cleanup_started_runtimes() {
  local -n runtimes_ref=$1
  for runtime in "${runtimes_ref[@]}"; do
    (
      cd "$REPO_ROOT"
      deploy/operators/dkg/operator.sh stop --workdir "$runtime" >/dev/null 2>&1 || true
    )
  done
}

command_run() {
  shift || true

  local workdir="$REPO_ROOT/tmp/testnet-e2e/dkg"
  local operator_count=5
  local threshold=3
  local network="testnet"
  local base_port=18443
  local release_tag="$JUNO_DKG_VERSION_DEFAULT"
  local output_path=""
  local force="false"
  local leave_running="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --operator-count)
        [[ $# -ge 2 ]] || die "missing value for --operator-count"
        operator_count="$2"
        shift 2
        ;;
      --threshold)
        [[ $# -ge 2 ]] || die "missing value for --threshold"
        threshold="$2"
        shift 2
        ;;
      --network)
        [[ $# -ge 2 ]] || die "missing value for --network"
        network="$2"
        shift 2
        ;;
      --base-port)
        [[ $# -ge 2 ]] || die "missing value for --base-port"
        base_port="$2"
        shift 2
        ;;
      --release-tag)
        [[ $# -ge 2 ]] || die "missing value for --release-tag"
        release_tag="$2"
        shift 2
        ;;
      --output)
        [[ $# -ge 2 ]] || die "missing value for --output"
        output_path="$2"
        shift 2
        ;;
      --force)
        force="true"
        shift
        ;;
      --leave-running)
        leave_running="true"
        shift
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

  [[ "$operator_count" =~ ^[0-9]+$ ]] || die "--operator-count must be numeric"
  [[ "$threshold" =~ ^[0-9]+$ ]] || die "--threshold must be numeric"
  [[ "$base_port" =~ ^[0-9]+$ ]] || die "--base-port must be numeric"
  (( operator_count >= 3 )) || die "--operator-count must be >= 3"
  (( threshold >= 2 )) || die "--threshold must be >= 2"
  (( threshold <= operator_count )) || die "--threshold must be <= --operator-count"

  if [[ -z "$output_path" ]]; then
    output_path="$workdir/reports/dkg-summary.json"
  fi

  ensure_base_dependencies
  ensure_command go
  ensure_dir "$(dirname "$output_path")"

  if [[ -d "$workdir" ]]; then
    if [[ "$force" != "true" ]]; then
      die "workdir already exists (use --force to overwrite): $workdir"
    fi
    rm -rf "$workdir"
  fi
  ensure_dir "$workdir/operators"
  ensure_dir "$workdir/reports"

  export JUNO_DKG_ALLOW_INSECURE_NETWORK=1

  local coordinator_workdir="$workdir/coordinator"
  local completion_report="$coordinator_workdir/reports/test-completiton.json"

  local -a operator_ids=()
  local -a operator_key_files=()
  local -a operator_registrations=()
  local -a operator_endpoints=()
  local -a operator_runtime_dirs=()
  local -a operator_backup_packages=()
  local -a operator_status_json=()
  local -a started_runtimes=()
  local cleanup_enabled="true"

  trap '
    if [[ "${cleanup_enabled:-true}" == "true" ]]; then
      cleanup_started_runtimes started_runtimes
    fi
  ' RETURN

  local i
  for ((i = 1; i <= operator_count; i++)); do
    local op_dir key_file meta_json registration_json endpoint port operator_id fee_recipient
    op_dir="$workdir/operators/op${i}"
    key_file="$op_dir/operator.key"
    meta_json="$op_dir/operator-meta.json"
    registration_json="$op_dir/registration.json"
    port=$((base_port + i - 1))
    endpoint="https://127.0.0.1:${port}"

    ensure_dir "$op_dir"
    (
      cd "$REPO_ROOT"
      go run ./cmd/operator-keygen -private-key-path "$key_file" >"$meta_json"
    )

    operator_id="$(jq -r '.operator_id' "$meta_json")"
    fee_recipient="$(jq -r '.fee_recipient' "$meta_json")"
    jq -n \
      --arg operator_id "$operator_id" \
      --arg fee_recipient "$fee_recipient" \
      --arg grpc_endpoint "$endpoint" \
      '{
        operator_id: $operator_id,
        fee_recipient: $fee_recipient,
        grpc_endpoint: $grpc_endpoint
      }' >"$registration_json"

    operator_ids+=("$operator_id")
    operator_key_files+=("$key_file")
    operator_registrations+=("$registration_json")
    operator_endpoints+=("$endpoint")
  done

  local -a coordinator_init_args=()
  coordinator_init_args+=(
    "--workdir" "$coordinator_workdir"
    "--network" "$network"
    "--threshold" "$threshold"
    "--max-signers" "$operator_count"
    "--release-tag" "$release_tag"
  )
  for registration in "${operator_registrations[@]}"; do
    coordinator_init_args+=("--registration-file" "$registration")
  done

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/coordinator.sh init "${coordinator_init_args[@]}"
  )

  for ((i = 1; i <= operator_count; i++)); do
    local operator_id slug bundle_path runtime_dir
    operator_id="${operator_ids[$((i - 1))]}"
    slug="$(safe_slug "$operator_id")"
    bundle_path="$(find "$coordinator_workdir/bundles" -maxdepth 1 -type f -name "*_${slug}.tar.gz" | head -n 1)"
    [[ -n "$bundle_path" ]] || die "bundle not found for operator $operator_id"

    runtime_dir="$workdir/operators/op${i}/runtime"
    (
      cd "$REPO_ROOT"
      deploy/operators/dkg/operator.sh run \
        --bundle "$bundle_path" \
        --workdir "$runtime_dir" \
        --release-tag "$release_tag" \
        --daemon
    )
    operator_runtime_dirs+=("$runtime_dir")
    started_runtimes+=("$runtime_dir")
  done

  (
    cd "$REPO_ROOT"
    deploy/operators/dkg/coordinator.sh preflight --workdir "$coordinator_workdir" --release-tag "$release_tag"
    deploy/operators/dkg/coordinator.sh run --workdir "$coordinator_workdir" --release-tag "$release_tag"
    deploy/operators/dkg/test-completiton.sh run \
      --workdir "$coordinator_workdir" \
      --skip-resume \
      --release-tag "$release_tag" \
      --output "$completion_report"
  )

  for ((i = 1; i <= operator_count; i++)); do
    local op_dir runtime_dir age_identity age_payload age_recipient age_backup backup_zip
    op_dir="$workdir/operators/op${i}"
    runtime_dir="$op_dir/runtime"
    age_identity="$op_dir/backup/age-identity.txt"
    age_payload="$op_dir/backup/age-recipient.json"
    age_backup="$op_dir/exports/keypackage-backup.json"
    backup_zip="$op_dir/backup-packages/dkg-backup.zip"

    ensure_dir "$op_dir/backup"
    ensure_dir "$op_dir/exports"
    ensure_dir "$op_dir/backup-packages"

    (
      cd "$REPO_ROOT"
      deploy/operators/dkg/operator-export-kms.sh age-recipient \
        --identity-file "$age_identity" \
        --output "$age_payload"
    )
    age_recipient="$(jq -r '.age_recipient' "$age_payload")"
    [[ "$age_recipient" =~ ^age1[0-9a-z]+$ ]] || die "invalid age recipient generated for op${i}"

    (
      cd "$REPO_ROOT"
      deploy/operators/dkg/operator-export-kms.sh backup-age \
        --workdir "$runtime_dir" \
        --release-tag "$release_tag" \
        --age-recipient "$age_recipient" \
        --out "$age_backup"

      deploy/operators/dkg/backup-package.sh create \
        --workdir "$runtime_dir" \
        --age-identity-file "$age_identity" \
        --age-backup-file "$age_backup" \
        --admin-config "$runtime_dir/bundle/admin-config.json" \
        --output "$backup_zip" \
        --force
    )

    operator_backup_packages+=("$backup_zip")
  done

  cleanup_started_runtimes started_runtimes
  started_runtimes=()

  for runtime_dir in "${operator_runtime_dirs[@]}"; do
    rm -rf "$runtime_dir"
  done

  for ((i = 1; i <= operator_count; i++)); do
    local runtime_dir backup_zip status_json
    runtime_dir="$workdir/operators/op${i}/runtime"
    backup_zip="$workdir/operators/op${i}/backup-packages/dkg-backup.zip"

    (
      cd "$REPO_ROOT"
      deploy/operators/dkg/backup-package.sh restore \
        --package "$backup_zip" \
        --workdir "$runtime_dir" \
        --force

      deploy/operators/dkg/operator.sh run \
        --bundle "$runtime_dir/bundle" \
        --workdir "$runtime_dir" \
        --release-tag "$release_tag" \
        --daemon
    )
    started_runtimes+=("$runtime_dir")

    status_json="$(
      cd "$REPO_ROOT"
      deploy/operators/dkg/operator.sh status --workdir "$runtime_dir"
    )"
    if [[ "$(printf '%s' "$status_json" | jq -r '.running')" != "true" ]]; then
      die "restored operator is not running: op${i}"
    fi
    operator_status_json+=("$status_json")
  done

  local operators_json='[]'
  for ((i = 1; i <= operator_count; i++)); do
    local idx op_json
    idx=$((i - 1))
    op_json="$(jq -n \
      --argjson index "$i" \
      --arg operator_id "${operator_ids[$idx]}" \
      --arg operator_key_file "${operator_key_files[$idx]}" \
      --arg registration_file "${operator_registrations[$idx]}" \
      --arg endpoint "${operator_endpoints[$idx]}" \
      --arg runtime_dir "${operator_runtime_dirs[$idx]}" \
      --arg backup_package "${operator_backup_packages[$idx]}" \
      --argjson status "${operator_status_json[$idx]}" \
      '{
        index: $index,
        operator_id: $operator_id,
        operator_key_file: $operator_key_file,
        registration_file: $registration_file,
        endpoint: $endpoint,
        runtime_dir: $runtime_dir,
        backup_package: $backup_package,
        status: $status
      }')"
    operators_json="$(jq --argjson op "$op_json" '. + [$op]' <<<"$operators_json")"
  done

  jq -n \
    --arg generated_at "$(timestamp_utc)" \
    --arg workdir "$workdir" \
    --arg coordinator_workdir "$coordinator_workdir" \
    --arg completion_report "$completion_report" \
    --arg network "$network" \
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
      operators: $operators
    }' >"$output_path"

  if [[ "$leave_running" != "true" ]]; then
    cleanup_started_runtimes started_runtimes
    started_runtimes=()
    cleanup_enabled="false"
  else
    cleanup_enabled="false"
  fi

  log "dkg backup/restore flow complete"
  log "summary=$output_path"
  printf '%s\n' "$output_path"
}

main() {
  local cmd="${1:-run}"
  case "$cmd" in
    run) command_run "$@" ;;
    -h|--help|"")
      usage
      ;;
    *)
      usage
      die "unsupported command: $cmd"
      ;;
  esac
}

main "$@"
