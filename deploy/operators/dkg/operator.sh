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
  operator.sh register [tailscale.sh register args...]
  operator.sh run [options]
  operator.sh status [options]
  operator.sh stop [options]

Commands:
  register                  Delegates to tailscale.sh register for operator registration JSON.

  run options:
    --bundle <path>         required bundle directory or .tar.gz created by coordinator.sh init
    --workdir <path>        runtime directory (default: ~/.juno-dkg/operator-runtime)
    --release-tag <tag>     dkg-admin release tag (default: v0.1.0)
    --daemon                run in background and return

  status options:
    --workdir <path>        runtime directory (default: ~/.juno-dkg/operator-runtime)

  stop options:
    --workdir <path>        runtime directory (default: ~/.juno-dkg/operator-runtime)
EOF
}

extract_bundle() {
  local bundle="$1"
  local dst="$2"

  if [[ -d "$bundle" ]]; then
    local bundle_abs dst_abs
    bundle_abs="$(cd "$bundle" && pwd -P)"
    dst_abs="$(mkdir -p "$dst" && cd "$dst" && pwd -P)"
    if [[ "$bundle_abs" == "$dst_abs" ]]; then
      return
    fi
  fi

  rm -rf "$dst"
  ensure_dir "$dst"

  if [[ -d "$bundle" ]]; then
    cp -R "$bundle"/. "$dst"/
    return
  fi
  if [[ -f "$bundle" && "$bundle" == *.tar.gz ]]; then
    tar -xzf "$bundle" -C "$dst"
    return
  fi
  die "bundle must be a directory or .tar.gz: $bundle"
}

command_register() {
  shift || true
  exec "$SCRIPT_DIR/tailscale.sh" register "$@"
}

command_run() {
  shift || true

  local bundle=""
  local workdir="$JUNO_DKG_HOME_DEFAULT/operator-runtime"
  local release_tag="$JUNO_DKG_VERSION_DEFAULT"
  local daemon="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bundle)
        [[ $# -ge 2 ]] || die "missing value for --bundle"
        bundle="$2"
        shift 2
        ;;
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
      --daemon)
        daemon="true"
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

  [[ -n "$bundle" ]] || die "--bundle is required"
  require_tailscale_active

  local runtime_bundle="$workdir/bundle"
  local pid_file="$workdir/dkg-admin.pid"
  local log_file="$workdir/dkg-admin.log"
  local bin_dir="$workdir/bin"

  ensure_dir "$workdir"
  extract_bundle "$bundle" "$runtime_bundle"

  local config_path="$runtime_bundle/admin-config.json"
  [[ -f "$config_path" ]] || die "bundle missing admin-config.json"
  [[ -f "$runtime_bundle/tls/ca.pem" ]] || die "bundle missing tls/ca.pem"
  [[ -f "$runtime_bundle/tls/server.pem" ]] || die "bundle missing tls/server.pem"
  [[ -f "$runtime_bundle/tls/server.key" ]] || die "bundle missing tls/server.key"

  local dkg_admin_bin
  dkg_admin_bin="$(ensure_dkg_binary "dkg-admin" "$release_tag" "$bin_dir")"

  if [[ -f "$pid_file" ]]; then
    local existing_pid
    existing_pid="$(cat "$pid_file")"
    if [[ -n "$existing_pid" ]] && kill -0 "$existing_pid" 2>/dev/null; then
      die "dkg-admin already running with pid $existing_pid"
    fi
    rm -f "$pid_file"
  fi

  if [[ "$daemon" == "true" ]]; then
    nohup bash -c '
      set -euo pipefail
      cd "$1"
      exec "$2" --config "./admin-config.json" serve
    ' _ "$runtime_bundle" "$dkg_admin_bin" >>"$log_file" 2>&1 &
    local pid=$!
    printf '%s\n' "$pid" >"$pid_file"
    log "dkg-admin started in background pid=$pid"
    log "log_file=$log_file"
    return
  fi

  cd "$runtime_bundle"
  exec "$dkg_admin_bin" --config "./admin-config.json" serve
}

command_status() {
  shift || true
  local workdir="$JUNO_DKG_HOME_DEFAULT/operator-runtime"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      *)
        die "unknown argument for status: $1"
        ;;
    esac
  done

  require_tailscale_active
  local pid_file="$workdir/dkg-admin.pid"
  local config_path="$workdir/bundle/admin-config.json"
  if [[ ! -f "$config_path" ]]; then
    die "missing operator config: $config_path"
  fi

  local running="false"
  local pid=""
  if [[ -f "$pid_file" ]]; then
    pid="$(cat "$pid_file")"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      running="true"
    fi
  fi

  jq -n \
    --arg running "$running" \
    --arg pid "$pid" \
    --arg listen_addr "$(jq -r '.grpc.listen_addr' "$config_path")" \
    --arg operator_id "$(jq -r '.operator_id' "$config_path")" \
    --arg ceremony_id "$(jq -r '.ceremony_id' "$config_path")" \
    '{
      running: ($running == "true"),
      pid: (if $pid == "" then null else ($pid|tonumber) end),
      operator_id: $operator_id,
      ceremony_id: $ceremony_id,
      listen_addr: $listen_addr
    }'
}

command_stop() {
  shift || true
  local workdir="$JUNO_DKG_HOME_DEFAULT/operator-runtime"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --workdir)
        [[ $# -ge 2 ]] || die "missing value for --workdir"
        workdir="$2"
        shift 2
        ;;
      *)
        die "unknown argument for stop: $1"
        ;;
    esac
  done

  local pid_file="$workdir/dkg-admin.pid"
  if [[ ! -f "$pid_file" ]]; then
    log "no pid file found: $pid_file"
    return
  fi
  local pid
  pid="$(cat "$pid_file")"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    log "sent TERM to pid=$pid"
  fi
  rm -f "$pid_file"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    register) command_register "$@" ;;
    run) command_run "$@" ;;
    status) command_status "$@" ;;
    stop) command_stop "$@" ;;
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
