#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"
prepare_script_runtime "$SCRIPT_DIR"

usage() {
  cat <<'EOF'
Usage:
  coordinator.sh init [options]
  coordinator.sh preflight [options]
  coordinator.sh run [options]
  coordinator.sh resume [options]
  coordinator.sh export [options]

Commands:
  init:
    --workdir <path>                 required ceremony workspace path
    --network <name>                 mainnet|testnet|regtest (default: mainnet)
    --threshold <n>                  required threshold
    --max-signers <n>                required participant count
    --ceremony-id <uuid>             optional (auto-generated if omitted)
    --release-tag <tag>              dkg-ceremony release tag (default: v0.1.0)
    --registration-file <path>       repeat for each operator registration JSON
    --prompt-endpoints               prompt to override endpoint per registration

  preflight/run/resume:
    --workdir <path>                 required
    --release-tag <tag>              dkg-ceremony release tag (default: v0.1.0)
    --connect-timeout-ms <ms>        default 10000
    --rpc-timeout-ms <ms>            default 30000
    --max-retries <n>                default 3
    --backoff-start-ms <ms>          default 250
    --backoff-max-ms <ms>            default 3000
    --jitter-ms <ms>                 default 100
    --retryable-codes <csv>          default unavailable,deadline_exceeded

  export:
    --workdir <path>                 required
    --release-tag <tag>              dkg-ceremony release tag (default: v0.1.0)
    --kms-key-id <arn>               required primary KMS export backend
    --s3-bucket <name>               required
    --s3-key-prefix <prefix>         required
    --s3-sse-kms-key-id <arn>        required
    --backup-age-recipient <age1..>  required local backup recipient (repeatable)
    --backup-remote-file-prefix <p>  default /var/tmp/juno-dkg-backup/keypackage
    --manifest-path <path>           default <workdir>/out/KeysetManifest.json
EOF
}

ensure_transport_primitives() {
  local workdir="$1"
  local cfg="$workdir/config/ceremony.json"
  [[ -f "$cfg" ]] || die "missing ceremony config: $cfg"
  [[ -f "$workdir/tls/ca.pem" ]] || die "missing tls CA cert: $workdir/tls/ca.pem"
  [[ -f "$workdir/tls/coordinator-client.pem" ]] || die "missing coordinator cert: $workdir/tls/coordinator-client.pem"
  [[ -f "$workdir/tls/coordinator-client.key" ]] || die "missing coordinator key: $workdir/tls/coordinator-client.key"
}

build_transport_flags() {
  local workdir="$1"
  local connect_timeout_ms="$2"
  local rpc_timeout_ms="$3"
  local max_retries="$4"
  local backoff_start_ms="$5"
  local backoff_max_ms="$6"
  local jitter_ms="$7"
  local retryable_codes="$8"

  TRANSPORT_FLAGS=(
    --tls-ca-cert-pem-path "$workdir/tls/ca.pem"
    --tls-client-cert-pem-path "$workdir/tls/coordinator-client.pem"
    --tls-client-key-pem-path "$workdir/tls/coordinator-client.key"
    --connect-timeout-ms "$connect_timeout_ms"
    --rpc-timeout-ms "$rpc_timeout_ms"
    --max-retries "$max_retries"
    --backoff-start-ms "$backoff_start_ms"
    --backoff-max-ms "$backoff_max_ms"
    --jitter-ms "$jitter_ms"
    --retryable-codes "$retryable_codes"
  )
}

collect_participants_from_prompt() {
  local max_signers="$1"
  local out_tsv="$2"
  : >"$out_tsv"

  local i operator_id fee_recipient grpc_endpoint
  for ((i = 1; i <= max_signers; i++)); do
    printf 'Participant %d operator_id (0x...): ' "$i" >&2
    read -r operator_id
    operator_id="$(normalize_eth_address "$operator_id")" || die "invalid operator_id for participant $i"

    printf 'Participant %d fee_recipient (0x...): ' "$i" >&2
    read -r fee_recipient
    fee_recipient="$(normalize_eth_address "$fee_recipient")" || die "invalid fee_recipient for participant $i"

    printf 'Participant %d grpc endpoint (https://host:port): ' "$i" >&2
    read -r grpc_endpoint
    parse_endpoint_host_port "$grpc_endpoint" >/dev/null || die "invalid grpc endpoint for participant $i: $grpc_endpoint"

    printf '%s\t%s\t%s\n' "$operator_id" "$fee_recipient" "$grpc_endpoint" >>"$out_tsv"
  done
}

collect_participants_from_files() {
  local max_signers="$1"
  local out_tsv="$2"
  local prompt_endpoints="$3"
  shift 3
  local registration_files=("$@")

  : >"$out_tsv"
  local file operator_id fee_recipient grpc_endpoint override
  for file in "${registration_files[@]}"; do
    [[ -f "$file" ]] || die "registration file not found: $file"
    operator_id="$(jq -r '.operator_id // ""' "$file")"
    fee_recipient="$(jq -r '.fee_recipient // ""' "$file")"
    grpc_endpoint="$(jq -r '.grpc_endpoint // ""' "$file")"

    operator_id="$(normalize_eth_address "$operator_id")" || die "invalid operator_id in $file"
    fee_recipient="$(normalize_eth_address "$fee_recipient")" || die "invalid fee_recipient in $file"
    parse_endpoint_host_port "$grpc_endpoint" >/dev/null || die "invalid grpc_endpoint in $file"

    if [[ "$prompt_endpoints" == "true" ]]; then
      printf 'Endpoint for %s [%s]: ' "$operator_id" "$grpc_endpoint" >&2
      read -r override
      override="$(trim "$override")"
      if [[ -n "$override" ]]; then
        parse_endpoint_host_port "$override" >/dev/null || die "invalid endpoint override: $override"
        grpc_endpoint="$override"
      fi
    fi

    printf '%s\t%s\t%s\n' "$operator_id" "$fee_recipient" "$grpc_endpoint" >>"$out_tsv"
  done

  local count
  count="$(wc -l <"$out_tsv" | tr -d ' ')"
  [[ "$count" == "$max_signers" ]] || die "registration count mismatch: expected $max_signers got $count"
}

validate_participants_tsv() {
  local tsv="$1"
  local max_signers="$2"

  local count
  count="$(wc -l <"$tsv" | tr -d ' ')"
  [[ "$count" == "$max_signers" ]] || die "participant count mismatch: expected $max_signers got $count"

  local dup_ops dup_eps
  dup_ops="$(cut -f1 "$tsv" | sort | uniq -d || true)"
  [[ -z "$dup_ops" ]] || die "duplicate operator_id entries found: $dup_ops"
  dup_eps="$(cut -f3 "$tsv" | sort | uniq -d || true)"
  [[ -z "$dup_eps" ]] || die "duplicate grpc_endpoint entries found: $dup_eps"
}

participants_tsv_to_json() {
  local tsv="$1"
  jq -R -s '
    split("\n")
    | map(select(length > 0))
    | map(split("\t"))
    | map({
        operator_id: .[0],
        fee_recipient: .[1],
        grpc_endpoint: .[2]
      })
  ' "$tsv"
}

compute_roster_hash_hex() {
  local roster_json="$1"
  local canonical
  canonical="$(printf '%s' "$roster_json" | jq -c '
    {
      roster_version: .roster_version,
      operators: (
        .operators
        | map({
            operator_id: (.operator_id | tostring | gsub("^\\s+|\\s+$"; "")),
            grpc_endpoint: (
              if .grpc_endpoint == null then null
              else (.grpc_endpoint | tostring | gsub("^\\s+|\\s+$"; ""))
              end
            ),
            age_recipient: (
              if .age_recipient == null then null
              else (.age_recipient | tostring | gsub("^\\s+|\\s+$"; ""))
              end
            )
          })
        | sort_by(.operator_id)
        | map(with_entries(select(.value != null)))
      ),
      coordinator_age_recipient: (
        if .coordinator_age_recipient == null then null
        else (.coordinator_age_recipient | tostring | gsub("^\\s+|\\s+$"; ""))
        end
      )
    }
    | with_entries(select(.value != null))
  ')"
  printf '%s' "$canonical" | sha256_hex_stdin
}

write_operator_bundles() {
  local workdir="$1"
  local ceremony_config="$2"
  local participants_json_path="$3"
  local roster_json_path="$4"
  local roster_hash_hex="$5"

  local fingerprint
  fingerprint="$(tr -d '\n' <"$workdir/tls/coordinator_client_cert_sha256.hex")"
  local tls_inventory="$workdir/tls/tls_material.json"
  [[ -f "$tls_inventory" ]] || die "missing tls inventory: $tls_inventory"

  local sorted_ops
  sorted_ops="$(jq -r '.operators | sort_by(.operator_id)[] | .operator_id' "$roster_json_path")"
  local identifier=0
  while IFS= read -r operator_id; do
    [[ -n "$operator_id" ]] || continue
    identifier=$((identifier + 1))

    local endpoint fee_recipient port host
    endpoint="$(jq -r --arg op "$operator_id" '.[] | select(.operator_id == $op) | .grpc_endpoint' "$participants_json_path")"
    fee_recipient="$(jq -r --arg op "$operator_id" '.[] | select(.operator_id == $op) | .fee_recipient' "$participants_json_path")"
    read -r host port <<<"$(parse_endpoint_host_port "$endpoint")" || die "invalid endpoint for $operator_id: $endpoint"

    local cert_src key_src
    cert_src="$(jq -r --arg op "$operator_id" '.operators[] | select(.operator_id == $op) | .server_cert_pem_path' "$tls_inventory")"
    key_src="$(jq -r --arg op "$operator_id" '.operators[] | select(.operator_id == $op) | .server_key_pem_path' "$tls_inventory")"
    [[ -f "$cert_src" ]] || die "missing server cert for $operator_id"
    [[ -f "$key_src" ]] || die "missing server key for $operator_id"

    local slug bundle_dir tar_path
    slug="$(safe_slug "$operator_id")"
    bundle_dir="$workdir/bundles/${identifier}_${slug}"
    tar_path="$workdir/bundles/${identifier}_${slug}.tar.gz"
    rm -rf "$bundle_dir" "$tar_path"
    ensure_dir "$bundle_dir/tls"

    cp "$workdir/tls/ca.pem" "$bundle_dir/tls/ca.pem"
    cp "$cert_src" "$bundle_dir/tls/server.pem"
    cp "$key_src" "$bundle_dir/tls/server.key"
    chmod 0600 "$bundle_dir/tls/server.key"

    local roster_json
    roster_json="$(cat "$roster_json_path")"

    jq -n \
      --arg ceremony_id "$(jq -r '.ceremony_id' "$ceremony_config")" \
      --arg operator_id "$operator_id" \
      --argjson identifier "$identifier" \
      --argjson threshold "$(jq -r '.threshold' "$ceremony_config")" \
      --argjson max_signers "$(jq -r '.max_signers' "$ceremony_config")" \
      --arg network "$(jq -r '.network' "$ceremony_config")" \
      --argjson roster "$roster_json" \
      --arg roster_hash_hex "$roster_hash_hex" \
      --arg listen_addr "0.0.0.0:$port" \
      --arg coordinator_client_cert_sha256 "$fingerprint" \
      '{
        config_version: 1,
        ceremony_id: $ceremony_id,
        operator_id: $operator_id,
        identifier: $identifier,
        threshold: $threshold,
        max_signers: $max_signers,
        network: $network,
        roster: $roster,
        roster_hash_hex: $roster_hash_hex,
        state_dir: "./state",
        age_identity_file: null,
        grpc: {
          listen_addr: $listen_addr,
          tls_ca_cert_pem_path: "./tls/ca.pem",
          tls_server_cert_pem_path: "./tls/server.pem",
          tls_server_key_pem_path: "./tls/server.key",
          coordinator_client_cert_sha256: $coordinator_client_cert_sha256
        }
      }' >"$bundle_dir/admin-config.json"

    jq -n \
      --arg operator_id "$operator_id" \
      --arg fee_recipient "$fee_recipient" \
      --arg grpc_endpoint "$endpoint" \
      --arg host "$host" \
      --argjson port "$port" \
      '{
        operator_id: $operator_id,
        fee_recipient: $fee_recipient,
        grpc_endpoint: $grpc_endpoint,
        endpoint_host: $host,
        endpoint_port: $port
      }' >"$bundle_dir/operator-metadata.json"

    cat >"$bundle_dir/README.txt" <<EOF
This bundle is for operator_id=$operator_id

Start command:
  dkg-admin --config ./admin-config.json serve

Files:
  admin-config.json
  tls/ca.pem
  tls/server.pem
  tls/server.key
  operator-metadata.json
EOF

    tar -czf "$tar_path" -C "$bundle_dir" .
    log "wrote bundle: $tar_path"
  done <<<"$sorted_ops"
}

command_init() {
  shift || true
  local workdir=""
  local network="mainnet"
  local threshold=""
  local max_signers=""
  local ceremony_id=""
  local release_tag="$JUNO_DKG_VERSION_DEFAULT"
  local prompt_endpoints="false"
  local registration_files=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --network)
        [[ $# -ge 2 ]] || die "missing value for --network"
        network="$(lower "$2")"
        shift 2
        ;;
      --threshold)
        [[ $# -ge 2 ]] || die "missing value for --threshold"
        threshold="$2"
        shift 2
        ;;
      --max-signers)
        [[ $# -ge 2 ]] || die "missing value for --max-signers"
        max_signers="$2"
        shift 2
        ;;
      --ceremony-id)
        [[ $# -ge 2 ]] || die "missing value for --ceremony-id"
        ceremony_id="$(lower "$2")"
        shift 2
        ;;
      --release-tag)
        [[ $# -ge 2 ]] || die "missing value for --release-tag"
        release_tag="$2"
        shift 2
        ;;
      --registration-file)
        [[ $# -ge 2 ]] || die "missing value for --registration-file"
        registration_files+=("$2")
        shift 2
        ;;
      --prompt-endpoints)
        prompt_endpoints="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for init: $1"
        ;;
    esac
  done

  [[ -n "$workdir" ]] || die "--workdir is required"
  [[ -n "$threshold" ]] || die "--threshold is required"
  [[ -n "$max_signers" ]] || die "--max-signers is required"
  [[ "$threshold" =~ ^[0-9]+$ ]] || die "threshold must be numeric"
  [[ "$max_signers" =~ ^[0-9]+$ ]] || die "max-signers must be numeric"
  (( threshold > 1 )) || die "threshold must be > 1"
  (( threshold <= max_signers )) || die "threshold must be <= max-signers"

  case "$network" in
    mainnet|testnet|regtest) ;;
    *) die "invalid --network: $network" ;;
  esac

  if [[ -z "$ceremony_id" ]]; then
    ceremony_id="$(generate_uuid)"
  fi

  ensure_base_dependencies
  ensure_dir "$workdir/config"
  ensure_dir "$workdir/reports"
  ensure_dir "$workdir/bundles"
  ensure_dir "$workdir/bin"

  local participants_tsv="$workdir/config/participants.tsv"
  if (( ${#registration_files[@]} > 0 )); then
    collect_participants_from_files "$max_signers" "$participants_tsv" "$prompt_endpoints" "${registration_files[@]}"
  else
    collect_participants_from_prompt "$max_signers" "$participants_tsv"
  fi
  validate_participants_tsv "$participants_tsv" "$max_signers"

  local participants_json roster_json roster_hash_hex
  participants_json="$(participants_tsv_to_json "$participants_tsv")"
  printf '%s\n' "$participants_json" >"$workdir/config/participants.json"

  roster_json="$(jq -n --argjson participants "$participants_json" '
    {
      roster_version: 1,
      operators: ($participants | map({
        operator_id: .operator_id,
        grpc_endpoint: .grpc_endpoint
      }))
    }')"
  printf '%s\n' "$roster_json" >"$workdir/config/roster.json"

  roster_hash_hex="$(compute_roster_hash_hex "$roster_json")"

  jq -n \
    --arg ceremony_id "$ceremony_id" \
    --arg network "$network" \
    --argjson threshold "$threshold" \
    --argjson max_signers "$max_signers" \
    --argjson roster "$roster_json" \
    --arg roster_hash_hex "$roster_hash_hex" \
    --arg out_dir "$workdir/out" \
    --arg transcript_dir "$workdir/transcript" \
    '{
      config_version: 1,
      ceremony_id: $ceremony_id,
      threshold: $threshold,
      max_signers: $max_signers,
      network: $network,
      roster: $roster,
      roster_hash_hex: $roster_hash_hex,
      out_dir: $out_dir,
      transcript_dir: $transcript_dir
    }' >"$workdir/config/ceremony.json"

  local dkg_ceremony_bin
  dkg_ceremony_bin="$(ensure_dkg_binary "dkg-ceremony" "$release_tag" "$workdir/bin")"
  "$dkg_ceremony_bin" --config "$workdir/config/ceremony.json" tls init --out-dir "$workdir/tls"

  write_operator_bundles \
    "$workdir" \
    "$workdir/config/ceremony.json" \
    "$workdir/config/participants.json" \
    "$workdir/config/roster.json" \
    "$roster_hash_hex"

  jq -n \
    --arg ceremony_id "$ceremony_id" \
    --arg network "$network" \
    --argjson threshold "$threshold" \
    --argjson max_signers "$max_signers" \
    --arg roster_hash_hex "$roster_hash_hex" \
    --arg participants_json_path "$workdir/config/participants.json" \
    --arg ceremony_config_path "$workdir/config/ceremony.json" \
    --arg bundles_dir "$workdir/bundles" \
    --arg created_at "$(timestamp_utc)" \
    '{
      setup_version: 1,
      created_at: $created_at,
      ceremony_id: $ceremony_id,
      network: $network,
      threshold: $threshold,
      max_signers: $max_signers,
      roster_hash_hex: $roster_hash_hex,
      participants_json_path: $participants_json_path,
      ceremony_config_path: $ceremony_config_path,
      bundles_dir: $bundles_dir
    }' >"$workdir/config/setup-summary.json"

  log "init complete"
  log "ceremony_id=$ceremony_id"
  log "roster_hash_hex=$roster_hash_hex"
  log "participants=$workdir/config/participants.json"
  log "bundles_dir=$workdir/bundles"
}

command_preflight_like() {
  local cmd="$1"
  shift
  local workdir=""
  local release_tag="$JUNO_DKG_VERSION_DEFAULT"
  local connect_timeout_ms="10000"
  local rpc_timeout_ms="30000"
  local max_retries="3"
  local backoff_start_ms="250"
  local backoff_max_ms="3000"
  local jitter_ms="100"
  local retryable_codes="unavailable,deadline_exceeded"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --release-tag)
        [[ $# -ge 2 ]] || die "missing value for --release-tag"
        release_tag="$2"
        shift 2
        ;;
      --connect-timeout-ms)
        connect_timeout_ms="$2"
        shift 2
        ;;
      --rpc-timeout-ms)
        rpc_timeout_ms="$2"
        shift 2
        ;;
      --max-retries)
        max_retries="$2"
        shift 2
        ;;
      --backoff-start-ms)
        backoff_start_ms="$2"
        shift 2
        ;;
      --backoff-max-ms)
        backoff_max_ms="$2"
        shift 2
        ;;
      --jitter-ms)
        jitter_ms="$2"
        shift 2
        ;;
      --retryable-codes)
        retryable_codes="$2"
        shift 2
        ;;
      *)
        die "unknown argument for $cmd: $1"
        ;;
    esac
  done

  [[ -n "$workdir" ]] || die "--workdir is required"
  require_tailscale_active
  ensure_transport_primitives "$workdir"
  ensure_dir "$workdir/reports"
  ensure_dir "$workdir/bin"

  local dkg_ceremony_bin
  dkg_ceremony_bin="$(ensure_dkg_binary "dkg-ceremony" "$release_tag" "$workdir/bin")"

  build_transport_flags \
    "$workdir" \
    "$connect_timeout_ms" \
    "$rpc_timeout_ms" \
    "$max_retries" \
    "$backoff_start_ms" \
    "$backoff_max_ms" \
    "$jitter_ms" \
    "$retryable_codes"

  case "$cmd" in
    preflight)
      "$dkg_ceremony_bin" --config "$workdir/config/ceremony.json" preflight \
        "${TRANSPORT_FLAGS[@]}" \
        --report-json "$workdir/reports/preflight.json"
      log "preflight report: $workdir/reports/preflight.json"
      ;;
    run)
      "$dkg_ceremony_bin" --config "$workdir/config/ceremony.json" online \
        "${TRANSPORT_FLAGS[@]}" \
        --state-dir "$workdir/online-state" \
        --report-json "$workdir/reports/online-run.json"
      log "online report: $workdir/reports/online-run.json"
      ;;
    resume)
      "$dkg_ceremony_bin" --config "$workdir/config/ceremony.json" online \
        "${TRANSPORT_FLAGS[@]}" \
        --state-dir "$workdir/online-state" \
        --resume \
        --report-json "$workdir/reports/online-resume.json"
      log "resume report: $workdir/reports/online-resume.json"
      ;;
    *)
      die "internal error: unsupported preflight-like command $cmd"
      ;;
  esac
}

command_export() {
  shift || true
  local workdir=""
  local release_tag="$JUNO_DKG_VERSION_DEFAULT"
  local manifest_path=""
  local kms_key_id=""
  local s3_bucket=""
  local s3_key_prefix=""
  local s3_sse_kms_key_id=""
  local backup_remote_file_prefix="/var/tmp/juno-dkg-backup/keypackage"
  local backup_age_recipients=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      --release-tag)
        [[ $# -ge 2 ]] || die "missing value for --release-tag"
        release_tag="$2"
        shift 2
        ;;
      --manifest-path)
        [[ $# -ge 2 ]] || die "missing value for --manifest-path"
        manifest_path="$2"
        shift 2
        ;;
      --kms-key-id)
        [[ $# -ge 2 ]] || die "missing value for --kms-key-id"
        kms_key_id="$2"
        shift 2
        ;;
      --s3-bucket)
        [[ $# -ge 2 ]] || die "missing value for --s3-bucket"
        s3_bucket="$2"
        shift 2
        ;;
      --s3-key-prefix)
        [[ $# -ge 2 ]] || die "missing value for --s3-key-prefix"
        s3_key_prefix="$2"
        shift 2
        ;;
      --s3-sse-kms-key-id)
        [[ $# -ge 2 ]] || die "missing value for --s3-sse-kms-key-id"
        s3_sse_kms_key_id="$2"
        shift 2
        ;;
      --backup-age-recipient)
        [[ $# -ge 2 ]] || die "missing value for --backup-age-recipient"
        backup_age_recipients+=("$2")
        shift 2
        ;;
      --backup-remote-file-prefix)
        [[ $# -ge 2 ]] || die "missing value for --backup-remote-file-prefix"
        backup_remote_file_prefix="$2"
        shift 2
        ;;
      *)
        die "unknown argument for export: $1"
        ;;
    esac
  done

  [[ -n "$workdir" ]] || die "--workdir is required"
  [[ -n "$kms_key_id" ]] || die "--kms-key-id is required"
  [[ -n "$s3_bucket" ]] || die "--s3-bucket is required"
  [[ -n "$s3_key_prefix" ]] || die "--s3-key-prefix is required"
  [[ -n "$s3_sse_kms_key_id" ]] || die "--s3-sse-kms-key-id is required"
  (( ${#backup_age_recipients[@]} > 0 )) || die "at least one --backup-age-recipient is required"

  if [[ -z "$manifest_path" ]]; then
    manifest_path="$workdir/out/KeysetManifest.json"
  fi
  [[ -f "$manifest_path" ]] || die "manifest not found: $manifest_path"

  require_tailscale_active
  ensure_transport_primitives "$workdir"
  ensure_dir "$workdir/reports"
  ensure_dir "$workdir/bin"

  local dkg_ceremony_bin
  dkg_ceremony_bin="$(ensure_dkg_binary "dkg-ceremony" "$release_tag" "$workdir/bin")"

  build_transport_flags "$workdir" "10000" "30000" "3" "250" "3000" "100" "unavailable,deadline_exceeded"

  "$dkg_ceremony_bin" --config "$workdir/config/ceremony.json" export-key-packages \
    "${TRANSPORT_FLAGS[@]}" \
    --manifest-path "$manifest_path" \
    --receipts-dir "$workdir/out/export-receipts-kms" \
    --report-json "$workdir/reports/export-kms.json" \
    --kms-key-id "$kms_key_id" \
    --s3-bucket "$s3_bucket" \
    --s3-key-prefix "$s3_key_prefix" \
    --s3-sse-kms-key-id "$s3_sse_kms_key_id"

  local backup_args=()
  local recipient
  for recipient in "${backup_age_recipients[@]}"; do
    backup_args+=(--age-recipient "$recipient")
  done

  "$dkg_ceremony_bin" --config "$workdir/config/ceremony.json" export-key-packages \
    "${TRANSPORT_FLAGS[@]}" \
    --manifest-path "$manifest_path" \
    --receipts-dir "$workdir/out/export-receipts-backup-age" \
    --report-json "$workdir/reports/export-backup-age.json" \
    "${backup_args[@]}" \
    --remote-file-prefix "$backup_remote_file_prefix"

  log "kms export report: $workdir/reports/export-kms.json"
  log "backup export report: $workdir/reports/export-backup-age.json"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    init) command_init "$@" ;;
    preflight) command_preflight_like "preflight" "${@:2}" ;;
    run) command_preflight_like "run" "${@:2}" ;;
    resume) command_preflight_like "resume" "${@:2}" ;;
    export) command_export "$@" ;;
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
