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
  render-handoff.sh [options]
  render-handoff.sh validate --handoff-manifest <path>

Render options:
  --inventory <path>              deployment inventory json (required)
  --dkg-summary <path>            dkg summary json (required)
  --output-dir <path>             output root (default: ./production-output)
  --operator-id <id>              optional operator filter
  --secret-mode <mode>            auto|plain|age|none (default: auto)
  --age-recipient <age1..>        repeatable override used with --secret-mode age
  --shared-manifest-path <path>   optional shared-manifest path recorded in handoff json
  --rollout-state-file <path>     optional rollout-state path recorded in operator-deploy.json
  --validate                      run local restore validation for rendered bundles
  --force                         overwrite an existing operator handoff dir

Validate options:
  --handoff-manifest <path>       render-handoff manifest json produced by this script

Render output:
  <output-dir>/<environment>/handoff-manifest.json
  <output-dir>/<environment>/operators/<operator-id>/
    dkg-backup.zip
    backup-manifest.json
    admin-config.json
    test-completiton.json         (if present in backup package)
    known_hosts
    operator-secrets.env          (plain or placeholder mode)
    operator-secrets.env.age      (age mode)
    operator-deploy.json
    dkg-handoff.json
    handoff-validation.json
EOF
}

json_required() {
  local path="$1"
  local filter="$2"
  local msg="$3"
  local value
  if ! value="$(jq -er "$filter" "$path" 2>/dev/null)"; then
    die "$msg"
  fi
  printf '%s' "$value"
}

json_required_from_string() {
  local input="$1"
  local filter="$2"
  local msg="$3"
  local value
  if ! value="$(printf '%s' "$input" | jq -er "$filter" 2>/dev/null)"; then
    die "$msg"
  fi
  printf '%s' "$value"
}

json_optional_from_string() {
  local input="$1"
  local filter="$2"
  printf '%s' "$input" | jq -r "$filter // empty"
}

resolve_path() {
  local base_dir="$1"
  local target="$2"
  if [[ "$target" == /* ]]; then
    printf '%s\n' "$target"
    return
  fi
  (
    cd "$base_dir"
    cd "$(dirname "$target")"
    printf '%s/%s\n' "$PWD" "$(basename "$target")"
  )
}

copy_zip_member() {
  local zip_path="$1"
  local member="$2"
  local dest="$3"
  unzip -p "$zip_path" "$member" >"$dest"
}

infer_secret_mode() {
  local secret_src="$1"
  if [[ -n "$secret_src" ]]; then
    printf 'plain\n'
    return
  fi
  printf 'none\n'
}

placeholder_known_hosts() {
  local dest="$1"
  cat >"$dest" <<'EOF'
# placeholder known_hosts file
# replace this file with a pinned operator host entry before remote deployment
EOF
}

placeholder_secret_contract() {
  local dest="$1"
  cat >"$dest" <<'EOF'
# placeholder operator secret contract
# replace each value with a supported resolver before remote deployment
CHECKPOINT_POSTGRES_DSN=env:REPLACE_ME
BASE_RELAYER_AUTH_TOKEN=env:REPLACE_ME
EOF
}

encrypt_secret_contract() {
  local src="$1"
  local dest="$2"
  shift 2
  local -a recipients=("$@")
  (( ${#recipients[@]} > 0 )) || die "age secret handoff requires at least one recipient"

  local -a cmd=(age -o "$dest")
  local recipient
  for recipient in "${recipients[@]}"; do
    cmd+=(-r "$recipient")
  done
  cmd+=("$src")
  "${cmd[@]}"
}

collect_age_recipients() {
  local operator_json="$1"
  shift
  local -a recipients=("$@")
  if (( ${#recipients[@]} > 0 )); then
    printf '%s\n' "${recipients[@]}"
    return
  fi

  local inventory_age_recipient
  inventory_age_recipient="$(json_optional_from_string "$operator_json" '.age_recipient')"
  if [[ -n "$inventory_age_recipient" ]]; then
    printf '%s\n' "$inventory_age_recipient"
    return
  fi

  die "age secret handoff requires --age-recipient or inventory age_recipient"
}

build_dns_record_name() {
  local operator_json="$1"
  local environment="$2"
  local shared_manifest_path="$3"

  local explicit_record label subdomain
  explicit_record="$(json_optional_from_string "$operator_json" '.dns.record_name')"
  if [[ -n "$explicit_record" ]]; then
    printf '%s\n' "$explicit_record"
    return
  fi

  label="$(json_optional_from_string "$operator_json" '.public_dns_label')"
  if [[ -z "$label" ]]; then
    printf '%s\n' "$environment"
    return
  fi

  subdomain=""
  if [[ -n "$shared_manifest_path" && -f "$shared_manifest_path" ]]; then
    subdomain="$(jq -r '.dns.public_subdomain // empty' "$shared_manifest_path" 2>/dev/null || true)"
  fi
  if [[ -z "$subdomain" ]]; then
    printf '%s.%s\n' "$label" "$environment"
    return
  fi
  printf '%s.%s\n' "$label" "$subdomain"
}

write_operator_deploy() {
  local bundle_dir="$1"
  local operator_json="$2"
  local environment="$3"
  local shared_manifest_path="$4"
  local bundle_secret_file="$5"
  local bundle_known_hosts="$6"
  local bundle_backup="$7"
  local operator_id="$8"
  local operator_index="$9"
  local rollout_state_file="${10}"

  local bundle_rel known_hosts_rel secret_rel dns_mode dns_record_name ttl_seconds
  bundle_rel="operators/$operator_id"
  known_hosts_rel="$bundle_rel/$(basename "$bundle_known_hosts")"
  secret_rel="$bundle_rel/$(basename "$bundle_secret_file")"
  dns_mode="$(json_optional_from_string "$operator_json" '.dns.mode')"
  if [[ -z "$dns_mode" ]]; then
    dns_mode="public-zone"
  fi
  ttl_seconds="$(json_optional_from_string "$operator_json" '.dns.ttl_seconds')"
  if [[ -z "$ttl_seconds" ]]; then
    ttl_seconds="60"
  fi
  dns_record_name="$(build_dns_record_name "$operator_json" "$environment" "$shared_manifest_path")"

  jq -n \
    --arg version "1" \
    --arg environment "$environment" \
    --arg shared_manifest_path "$shared_manifest_path" \
    --arg rollout_state_file "$rollout_state_file" \
    --arg operator_id "$operator_id" \
    --argjson operator_index "$operator_index" \
    --arg aws_profile "$(json_optional_from_string "$operator_json" '.aws_profile')" \
    --arg aws_region "$(json_optional_from_string "$operator_json" '.aws_region')" \
    --arg account_id "$(json_optional_from_string "$operator_json" '.account_id')" \
    --arg operator_host "$(json_optional_from_string "$operator_json" '.operator_host')" \
    --arg operator_user "$(json_optional_from_string "$operator_json" '.operator_user')" \
    --arg runtime_dir "$(json_optional_from_string "$operator_json" '.runtime_dir')" \
    --arg public_endpoint "$(json_optional_from_string "$operator_json" '.public_endpoint')" \
    --arg dkg_backup_zip "$bundle_rel/$(basename "$bundle_backup")" \
    --arg known_hosts_file "$known_hosts_rel" \
    --arg secret_contract_file "$secret_rel" \
    --arg dns_mode "$dns_mode" \
    --arg dns_record_name "$dns_record_name" \
    --argjson ttl_seconds "$ttl_seconds" \
    '{
      version: $version,
      environment: $environment,
      shared_manifest_path: (if $shared_manifest_path == "" then null else $shared_manifest_path end),
      rollout_state_file: (if $rollout_state_file == "" then null else $rollout_state_file end),
      operator_id: $operator_id,
      operator_index: $operator_index,
      aws_profile: (if $aws_profile == "" then null else $aws_profile end),
      aws_region: (if $aws_region == "" then null else $aws_region end),
      account_id: (if $account_id == "" then null else $account_id end),
      operator_host: (if $operator_host == "" then null else $operator_host end),
      operator_user: (if $operator_user == "" then "ubuntu" else $operator_user end),
      runtime_dir: (if $runtime_dir == "" then "/var/lib/intents-juno/operator-runtime" else $runtime_dir end),
      dkg_backup_zip: $dkg_backup_zip,
      known_hosts_file: $known_hosts_file,
      secret_contract_file: $secret_contract_file,
      public_endpoint: (if $public_endpoint == "" then null else $public_endpoint end),
      dns: {
        mode: $dns_mode,
        record_name: $dns_record_name,
        ttl_seconds: $ttl_seconds
      }
    }' >"$bundle_dir/operator-deploy.json"
}

run_restore_validation() {
  local bundle_dir="$1"
  local operator_id="$2"
  local tmp_dir status detail
  tmp_dir="$(mktemp -d)"

  if bash "$SCRIPT_DIR/backup-package.sh" restore \
    --package "$bundle_dir/dkg-backup.zip" \
    --workdir "$tmp_dir/runtime" \
    --report "$tmp_dir/restore-report.json" >/dev/null 2>&1; then
    if [[ -f "$tmp_dir/runtime/bundle/admin-config.json" && -f "$tmp_dir/runtime/bundle/state/key_package.bin" && -f "$tmp_dir/runtime/bundle/state/public_key_package.bin" ]]; then
      status="passed"
      detail="restore succeeded from handoff backup"
    else
      status="failed"
      detail="restore completed without expected runtime files"
    fi
  else
    status="failed"
    detail="restore command failed"
  fi

  jq -n \
    --arg status "$status" \
    --arg detail "$detail" \
    --arg operator_id "$operator_id" \
    '{
      operator_id: $operator_id,
      status: $status,
      detail: $detail
    }'

  rm -rf "$tmp_dir"
}

render_validation_json() {
  local bundle_dir="$1"
  local operator_id="$2"
  local known_hosts_mode="$3"
  local secret_contract_mode="$4"
  local restore_status="$5"
  local restore_detail="$6"

  local ready="false"
  if [[ "$known_hosts_mode" == "provided" && "$secret_contract_mode" != "placeholder" && "$restore_status" == "passed" ]]; then
    ready="true"
  fi

  jq -n \
    --arg version "1" \
    --arg generated_at "$(timestamp_utc)" \
    --arg operator_id "$operator_id" \
    --arg known_hosts_mode "$known_hosts_mode" \
    --arg secret_contract_mode "$secret_contract_mode" \
    --arg restore_status "$restore_status" \
    --arg restore_detail "$restore_detail" \
    --argjson ready_for_deploy "$ready" \
    '{
      version: $version,
      generated_at: $generated_at,
      operator_id: $operator_id,
      ready_for_deploy: $ready_for_deploy,
      inputs: {
        known_hosts: $known_hosts_mode,
        secret_contract: $secret_contract_mode
      },
      restore_validation: {
        status: $restore_status,
        detail: $restore_detail
      }
    }' >"$bundle_dir/handoff-validation.json"
}

render_command() {
  local inventory=""
  local dkg_summary=""
  local output_root="./production-output"
  local operator_filter=""
  local secret_mode="auto"
  local shared_manifest_path=""
  local rollout_state_file=""
  local do_validate="false"
  local force="false"
  local -a age_recipients=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --inventory)
        inventory="$2"
        shift 2
        ;;
      --dkg-summary)
        dkg_summary="$2"
        shift 2
        ;;
      --output-dir)
        output_root="$2"
        shift 2
        ;;
      --operator-id)
        operator_filter="$2"
        shift 2
        ;;
      --secret-mode)
        secret_mode="$2"
        shift 2
        ;;
      --age-recipient)
        age_recipients+=("$2")
        shift 2
        ;;
      --shared-manifest-path)
        shared_manifest_path="$2"
        shift 2
        ;;
      --rollout-state-file)
        rollout_state_file="$2"
        shift 2
        ;;
      --validate)
        do_validate="true"
        shift
        ;;
      --force)
        force="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done

  [[ -n "$inventory" ]] || die "--inventory is required"
  [[ -f "$inventory" ]] || die "inventory not found: $inventory"
  [[ -n "$dkg_summary" ]] || die "--dkg-summary is required"
  [[ -f "$dkg_summary" ]] || die "dkg summary not found: $dkg_summary"
  case "$secret_mode" in
    auto|plain|age|none) ;;
    *) die "invalid --secret-mode: $secret_mode" ;;
  esac

  ensure_command jq
  have_cmd unzip || die "required command not found: unzip"
  if [[ "$secret_mode" == "age" ]]; then
    ensure_command age
  fi

  local inventory_dir dkg_summary_dir environment env_dir operator_count i
  local manifest_tmp rendered_count=0
  inventory_dir="$(cd "$(dirname "$inventory")" && pwd)"
  dkg_summary_dir="$(cd "$(dirname "$dkg_summary")" && pwd)"
  environment="$(json_required "$inventory" '.environment | select(type == "string" and length > 0)' "inventory missing environment")"
  env_dir="$output_root/$environment"
  mkdir -p "$env_dir/operators"
  manifest_tmp="$(mktemp)"
  : >"$manifest_tmp"

  operator_count="$(json_required "$inventory" '.operators | length' "inventory missing operators")"
  for ((i = 0; i < operator_count; i++)); do
    local operator_json operator_id operator_index dkg_operator_json backup_package_src
    local bundle_dir known_hosts_src known_hosts_file known_hosts_mode
    local secret_src bundle_secret_file rendered_secret_mode
    local completion_report_member restore_result_json restore_status restore_detail
    local backup_manifest_json backup_sha256 ufvk

    operator_json="$(jq -ce ".operators[$i]" "$inventory")"
    operator_id="$(json_required_from_string "$operator_json" '.operator_id | select(type == "string" and length > 0)' "inventory operator missing operator_id")"
    if [[ -n "$operator_filter" && "$operator_id" != "$operator_filter" ]]; then
      continue
    fi
    operator_index="$(json_required_from_string "$operator_json" '.index' "inventory operator missing index")"
    dkg_operator_json="$(jq -ce --arg operator_id "$operator_id" '.operators[] | select(.operator_id == $operator_id)' "$dkg_summary" 2>/dev/null || true)"
    [[ -n "$dkg_operator_json" ]] || die "dkg summary missing operator_id=$operator_id"

    backup_package_src="$(json_required_from_string "$dkg_operator_json" '.backup_package | select(type == "string" and length > 0)' "dkg summary missing backup_package for operator_id=$operator_id")"
    backup_package_src="$(resolve_path "$dkg_summary_dir" "$backup_package_src")"
    [[ -f "$backup_package_src" ]] || die "backup package not found for operator_id=$operator_id: $backup_package_src"

    bundle_dir="$env_dir/operators/$(safe_slug "$operator_id")"
    if [[ -e "$bundle_dir" ]]; then
      if [[ "$force" != "true" ]]; then
        die "handoff dir already exists (use --force to overwrite): $bundle_dir"
      fi
      rm -rf "$bundle_dir"
    fi
    mkdir -p "$bundle_dir"

    cp "$backup_package_src" "$bundle_dir/dkg-backup.zip"
    backup_sha256="$(sha256_hex_file "$bundle_dir/dkg-backup.zip")"
    copy_zip_member "$backup_package_src" manifest.json "$bundle_dir/backup-manifest.json" || die "backup package missing manifest.json: $backup_package_src"
    copy_zip_member "$backup_package_src" payload/admin-config.json "$bundle_dir/admin-config.json" || die "backup package missing payload/admin-config.json: $backup_package_src"
    completion_report_member="$(jq -r '.includes.completion_report // empty' "$bundle_dir/backup-manifest.json")"
    if [[ -n "$completion_report_member" ]]; then
      copy_zip_member "$backup_package_src" "$completion_report_member" "$bundle_dir/test-completiton.json" \
        || die "backup package completion report missing: $backup_package_src"
    fi

    known_hosts_src="$(json_optional_from_string "$operator_json" '.known_hosts_file')"
    known_hosts_file="$bundle_dir/known_hosts"
    if [[ -n "$known_hosts_src" ]]; then
      known_hosts_src="$(resolve_path "$inventory_dir" "$known_hosts_src")"
      [[ -f "$known_hosts_src" ]] || die "known_hosts file not found for operator_id=$operator_id: $known_hosts_src"
      cp "$known_hosts_src" "$known_hosts_file"
      known_hosts_mode="provided"
    else
      placeholder_known_hosts "$known_hosts_file"
      known_hosts_mode="placeholder"
    fi

    secret_src="$(json_optional_from_string "$operator_json" '.secret_contract_file')"
    rendered_secret_mode="$secret_mode"
    if [[ "$rendered_secret_mode" == "auto" ]]; then
      rendered_secret_mode="$(infer_secret_mode "$secret_src")"
    fi
    if [[ -n "$secret_src" ]]; then
      secret_src="$(resolve_path "$inventory_dir" "$secret_src")"
      [[ -f "$secret_src" ]] || die "secret contract file not found for operator_id=$operator_id: $secret_src"
    fi
    case "$rendered_secret_mode" in
      none)
        bundle_secret_file="$bundle_dir/operator-secrets.env"
        placeholder_secret_contract "$bundle_secret_file"
        rendered_secret_mode="placeholder"
        ;;
      plain)
        bundle_secret_file="$bundle_dir/operator-secrets.env"
        if [[ -n "$secret_src" ]]; then
          cp "$secret_src" "$bundle_secret_file"
        else
          placeholder_secret_contract "$bundle_secret_file"
          rendered_secret_mode="placeholder"
        fi
        ;;
      age)
        if [[ -z "$secret_src" ]]; then
          die "secret-mode age requires secret_contract_file for operator_id=$operator_id"
        fi
        bundle_secret_file="$bundle_dir/operator-secrets.env.age"
        mapfile -t resolved_recipients < <(collect_age_recipients "$operator_json" "${age_recipients[@]}")
        encrypt_secret_contract "$secret_src" "$bundle_secret_file" "${resolved_recipients[@]}"
        ;;
      *)
        die "unsupported secret mode: $rendered_secret_mode"
        ;;
    esac

    write_operator_deploy \
      "$bundle_dir" \
      "$operator_json" \
      "$environment" \
      "$shared_manifest_path" \
      "$bundle_secret_file" \
      "$known_hosts_file" \
      "$bundle_dir/dkg-backup.zip" \
      "$operator_id" \
      "$operator_index" \
      "$rollout_state_file"

    restore_status="skipped"
    restore_detail="rendered without local restore validation"
    if [[ "$do_validate" == "true" ]]; then
      restore_result_json="$(run_restore_validation "$bundle_dir" "$operator_id")"
      restore_status="$(json_required_from_string "$restore_result_json" '.status' "restore validation missing status")"
      restore_detail="$(json_required_from_string "$restore_result_json" '.detail' "restore validation missing detail")"
    fi

    render_validation_json "$bundle_dir" "$operator_id" "$known_hosts_mode" "$rendered_secret_mode" "$restore_status" "$restore_detail"
    ufvk="$(jq -r '.ufvk // empty' "$dkg_summary")"
    backup_manifest_json="$(cat "$bundle_dir/backup-manifest.json")"
    jq -n \
      --arg version "1" \
      --arg generated_at "$(timestamp_utc)" \
      --arg environment "$environment" \
      --arg operator_id "$operator_id" \
      --argjson operator_index "$operator_index" \
      --arg ceremony_id "$(jq -r '.ceremony_id // empty' "$bundle_dir/admin-config.json")" \
      --arg network "$(jq -r '.network // empty' "$bundle_dir/admin-config.json")" \
      --argjson threshold "$(jq -r '.threshold // 0' "$dkg_summary")" \
      --argjson max_signers "$(jq -r '.max_signers // 0' "$bundle_dir/admin-config.json")" \
      --arg ufvk "$ufvk" \
      --arg shared_manifest_path "$shared_manifest_path" \
      --arg backup_package "dkg-backup.zip" \
      --arg backup_package_sha256 "$backup_sha256" \
      --arg backup_manifest "backup-manifest.json" \
      --arg admin_config "admin-config.json" \
      --arg completion_report "$( [[ -f "$bundle_dir/test-completiton.json" ]] && printf '%s' test-completiton.json )" \
      --arg known_hosts_file "$(basename "$known_hosts_file")" \
      --arg secret_contract_file "$(basename "$bundle_secret_file")" \
      --arg secret_contract_mode "$rendered_secret_mode" \
      --arg runtime_dir "$(json_optional_from_string "$operator_json" '.runtime_dir')" \
      --argjson backup_manifest "$backup_manifest_json" \
      --argjson inventory_operator "$operator_json" \
      --argjson dkg_operator "$dkg_operator_json" \
      --slurpfile validation "$bundle_dir/handoff-validation.json" \
      '{
        version: $version,
        generated_at: $generated_at,
        environment: $environment,
        operator_id: $operator_id,
        operator_index: $operator_index,
        ceremony_id: (if $ceremony_id == "" then null else $ceremony_id end),
        network: (if $network == "" then null else $network end),
        threshold: $threshold,
        max_signers: $max_signers,
        ufvk: (if $ufvk == "" then null else $ufvk end),
        shared_manifest_path: (if $shared_manifest_path == "" then null else $shared_manifest_path end),
        bundle: {
          operator_dir: ".",
          dkg_backup_zip: $backup_package,
          dkg_backup_zip_sha256: $backup_package_sha256,
          backup_manifest: $backup_manifest,
          admin_config: $admin_config,
          completion_report: (if $completion_report == "" then null else $completion_report end),
          known_hosts_file: $known_hosts_file,
          secret_contract_file: $secret_contract_file,
          secret_mode: $secret_contract_mode,
          secret_contract_mode: $secret_contract_mode
        },
        restore_validation: {
          runtime_dir: (if $runtime_dir == "" then "/var/lib/intents-juno/operator-runtime" else $runtime_dir end),
          command: ("deploy/operators/dkg/backup-package.sh restore --package " + $backup_package + " --workdir " + (if $runtime_dir == "" then "/var/lib/intents-juno/operator-runtime" else $runtime_dir end)),
          status: $validation[0].restore_validation.status,
          detail: $validation[0].restore_validation.detail
        },
        ready_for_deploy: $validation[0].ready_for_deploy,
        backup_manifest: $backup_manifest,
        inventory_operator: $inventory_operator,
        dkg_summary_operator: $dkg_operator
      }' >"$bundle_dir/dkg-handoff.json"

    jq -n \
      --arg operator_id "$operator_id" \
      --arg bundle_dir "operators/$operator_id" \
      --arg operator_deploy "operators/$operator_id/operator-deploy.json" \
      --arg handoff "operators/$operator_id/dkg-handoff.json" \
      --arg validation "operators/$operator_id/handoff-validation.json" \
      --slurpfile validation_json "$bundle_dir/handoff-validation.json" \
      '{
        operator_id: $operator_id,
        bundle_dir: $bundle_dir,
        operator_deploy: $operator_deploy,
        dkg_handoff: $handoff,
        validation: $validation,
        ready_for_deploy: $validation_json[0].ready_for_deploy,
        restore_validation: $validation_json[0].restore_validation
      }' >>"$manifest_tmp"

    rendered_count=$((rendered_count + 1))
    log "rendered operator handoff: $bundle_dir"
  done

  if [[ -n "$operator_filter" && "$rendered_count" -eq 0 ]]; then
    die "operator not present in inventory: $operator_filter"
  fi
  (( rendered_count > 0 )) || die "no operator handoffs rendered"

  jq -s \
    --arg version "1" \
    --arg generated_at "$(timestamp_utc)" \
    --arg environment "$environment" \
    --arg shared_manifest_path "$shared_manifest_path" \
    '{
      version: $version,
      generated_at: $generated_at,
      environment: $environment,
      shared_manifest_path: (if $shared_manifest_path == "" then null else $shared_manifest_path end),
      operators: .
    }' "$manifest_tmp" >"$env_dir/handoff-manifest.json"

  rm -f "$manifest_tmp"
  log "rendered $rendered_count operator handoff bundle(s)"
}

validate_command() {
  local handoff_manifest=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --handoff-manifest)
        handoff_manifest="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option for validate: $1"
        ;;
    esac
  done

  [[ -n "$handoff_manifest" ]] || die "--handoff-manifest is required"
  [[ -f "$handoff_manifest" ]] || die "handoff manifest not found: $handoff_manifest"
  ensure_command jq

  local manifest_dir overall_ready="true"
  manifest_dir="$(cd "$(dirname "$handoff_manifest")" && pwd)"

  local summary_json
  summary_json="$(jq -n \
    --arg environment "$(jq -r '.environment' "$handoff_manifest")" \
    --arg version "1" \
    --arg validated_at "$(timestamp_utc)" \
    '{
      version: $version,
      validated_at: $validated_at,
      environment: $environment,
      ready_for_deploy: true,
      operators: []
    }')"

  local operator_count i operator_entry validation_rel validation_path ready
  operator_count="$(jq -r '.operators | length' "$handoff_manifest")"
  for ((i = 0; i < operator_count; i++)); do
    operator_entry="$(jq -ce ".operators[$i]" "$handoff_manifest")"
    validation_rel="$(json_required_from_string "$operator_entry" '.validation' "handoff manifest operator missing validation path")"
    validation_path="$(resolve_path "$manifest_dir" "$validation_rel")"
    [[ -f "$validation_path" ]] || die "handoff validation file not found: $validation_path"
    ready="$(jq -r '.ready_for_deploy' "$validation_path")"
    if [[ "$ready" != "true" ]]; then
      overall_ready="false"
    fi
    summary_json="$(jq \
      --argjson validation "$(cat "$validation_path")" \
      '.operators += [$validation]' <<<"$summary_json")"
  done

  summary_json="$(jq --argjson ready "$overall_ready" '.ready_for_deploy = $ready' <<<"$summary_json")"
  printf '%s\n' "$summary_json"
  [[ "$overall_ready" == "true" ]]
}

main() {
  local cmd="render"
  if [[ "${1:-}" == "validate" ]]; then
    cmd="validate"
    shift
  fi

  case "$cmd" in
    render)
      render_command "$@"
      ;;
    validate)
      validate_command "$@"
      ;;
    *)
      usage
      die "unsupported command: $cmd"
      ;;
  esac
}

main "$@"
