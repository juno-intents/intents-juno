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
  test-completiton.sh run [options]

Options:
  --workdir <path>          required ceremony workspace path
  --release-tag <tag>       dkg-ceremony release tag (default: v0.1.0)
  --skip-resume             do not run coordinator.sh resume before validation
  --output <path>           output summary json (default: <workdir>/reports/test-completiton.json)

This command:
  1) Optionally runs `coordinator.sh resume` to execute resumable online flow (includes smoke signatures)
  2) Verifies online report success + smoke signature phases for every operator
  3) Extracts UFVK and Juno shielded address from KeysetManifest
EOF
}

select_online_report_path() {
  local workdir="$1"
  local resume_report="$workdir/reports/online-resume.json"
  local run_report="$workdir/reports/online-run.json"
  if [[ -f "$resume_report" ]]; then
    printf '%s' "$resume_report"
    return
  fi
  if [[ -f "$run_report" ]]; then
    printf '%s' "$run_report"
    return
  fi
  die "online report not found: expected $resume_report or $run_report"
}

verify_smoke_signatures() {
  local report_path="$1"
  local required=(smoke_standard_commit smoke_standard_share smoke_randomized_commit smoke_randomized_share)

  local success
  success="$(jq -r '.success // false' "$report_path")"
  [[ "$success" == "true" ]] || die "online report indicates failure: $report_path"

  local op_count
  op_count="$(jq '.operator_reports | length' "$report_path")"
  (( op_count > 0 )) || die "operator_reports is empty in $report_path"

  local phase
  for phase in "${required[@]}"; do
    local missing
    missing="$(jq -r --arg phase "$phase" '
      [
        .operator_reports[]
        | select((.phase_timings_ms[$phase] // null) == null)
        | .operator_id
      ] | join(",")
    ' "$report_path")"
    [[ -z "$missing" ]] || die "missing smoke phase $phase for operators: $missing"

    local failed
    failed="$(jq -r --arg phase "$phase" '
      [
        .operator_reports[]
        | select((.phase_error_codes[$phase] // null) != null)
        | "\(.operator_id):\(.phase_error_codes[$phase])"
      ] | join(",")
    ' "$report_path")"
    [[ -z "$failed" ]] || die "smoke phase $phase failed: $failed"
  done
}

command_run() {
  shift || true

  local workdir=""
  local release_tag="$JUNO_DKG_VERSION_DEFAULT"
  local skip_resume="false"
  local output=""

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
      --skip-resume)
        skip_resume="true"
        shift
        ;;
      --output)
        [[ $# -ge 2 ]] || die "missing value for --output"
        output="$2"
        shift 2
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

  [[ -n "$workdir" ]] || die "--workdir is required"
  [[ -d "$workdir" ]] || die "workdir not found: $workdir"

  ensure_base_dependencies
  ensure_dir "$workdir/reports"
  if [[ -z "$output" ]]; then
    output="$workdir/reports/test-completiton.json"
  fi

  if [[ "$skip_resume" != "true" ]]; then
    "$SCRIPT_DIR/coordinator.sh" resume --workdir "$workdir" --release-tag "$release_tag"
  fi

  local report_path manifest_path
  report_path="$(select_online_report_path "$workdir")"
  manifest_path="$workdir/out/KeysetManifest.json"
  [[ -f "$manifest_path" ]] || die "manifest not found: $manifest_path"

  verify_smoke_signatures "$report_path"

  local ceremony_hash ufvk ua pk_hash transcript_hash threshold max_signers network
  ceremony_hash="$(jq -r '.ceremony_hash' "$report_path")"
  ufvk="$(jq -r '.ufvk // ""' "$manifest_path")"
  ua="$(jq -r '.owallet_ua // ""' "$manifest_path")"
  pk_hash="$(jq -r '.public_key_package_hash // ""' "$manifest_path")"
  transcript_hash="$(jq -r '.transcript_hash // ""' "$manifest_path")"
  threshold="$(jq -r '.threshold' "$manifest_path")"
  max_signers="$(jq -r '.max_signers' "$manifest_path")"
  network="$(jq -r '.network' "$manifest_path")"

  [[ -n "$ufvk" ]] || die "manifest missing ufvk"
  [[ -n "$ua" ]] || die "manifest missing owallet_ua"
  [[ -n "$pk_hash" ]] || die "manifest missing public_key_package_hash"
  [[ -n "$transcript_hash" ]] || die "manifest missing transcript_hash"

  local summary
  summary="$(jq -n \
    --arg generated_at "$(timestamp_utc)" \
    --arg ceremony_hash "$ceremony_hash" \
    --arg online_report_path "$report_path" \
    --arg manifest_path "$manifest_path" \
    --arg network "$network" \
    --argjson threshold "$threshold" \
    --argjson max_signers "$max_signers" \
    --arg ufvk "$ufvk" \
    --arg juno_shielded_address "$ua" \
    --arg public_key_package_hash "$pk_hash" \
    --arg transcript_hash "$transcript_hash" \
    '{
      report_version: 1,
      generated_at: $generated_at,
      ceremony_hash: $ceremony_hash,
      network: $network,
      threshold: $threshold,
      max_signers: $max_signers,
      online_report_path: $online_report_path,
      manifest_path: $manifest_path,
      test_signature: {
        status: "passed",
        phases: [
          "smoke_standard_commit",
          "smoke_standard_share",
          "smoke_randomized_commit",
          "smoke_randomized_share"
        ]
      },
      ufvk: $ufvk,
      juno_shielded_address: $juno_shielded_address,
      public_key_package_hash: $public_key_package_hash,
      transcript_hash: $transcript_hash
    }'
  )"

  ensure_dir "$(dirname "$output")"
  printf '%s\n' "$summary" >"$output"
  chmod 0644 "$output" || true

  printf '%s\n' "$summary"
  log "completion summary: $output"
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
