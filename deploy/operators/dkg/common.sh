#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

JUNO_DKG_VERSION_DEFAULT="${JUNO_DKG_VERSION_DEFAULT:-v0.1.0}"
JUNO_TXSIGN_VERSION_DEFAULT="${JUNO_TXSIGN_VERSION_DEFAULT:-v1.4}"
JUNO_DKG_HOME_DEFAULT="${JUNO_DKG_HOME_DEFAULT:-$HOME/.juno-dkg}"

_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$_SCRIPT_DIR/../../.." && pwd)"

log() {
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

safe_slug() {
  local out
  out="$(printf '%s' "$1" | tr -cs '[:alnum:]_.-' '_')"
  out="${out##_}"
  out="${out%%_}"
  if [[ -z "$out" ]]; then
    out="value"
  fi
  printf '%s' "$out"
}

build_export_s3_key() {
  local prefix="$1"
  local ceremony_id="$2"
  local operator_id="$3"
  local identifier="$4"

  prefix="$(trim "$prefix")"
  prefix="${prefix#/}"
  prefix="${prefix%/}"

  ceremony_id="$(safe_slug "$ceremony_id")"
  operator_id="$(safe_slug "$operator_id")"
  identifier="$(safe_slug "$identifier")"

  local leaf="operator_${identifier}_${operator_id}.json"
  if [[ -n "$prefix" ]]; then
    printf '%s/%s/%s' "$prefix" "$ceremony_id" "$leaf"
    return
  fi
  printf '%s/%s' "$ceremony_id" "$leaf"
}

detect_os() {
  local os_override="${JUNO_DKG_OS_OVERRIDE:-}"
  if [[ -n "$os_override" ]]; then
    case "$os_override" in
      darwin|linux)
        printf '%s' "$os_override"
        return
        ;;
      *)
        die "invalid JUNO_DKG_OS_OVERRIDE: $os_override"
        ;;
    esac
  fi

  local os
  os="$(uname -s)"
  case "$os" in
    Darwin) printf 'darwin' ;;
    Linux) printf 'linux' ;;
    *) die "unsupported OS: $os" ;;
  esac
}

detect_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) printf 'amd64' ;;
    arm64|aarch64) printf 'arm64' ;;
    *) die "unsupported architecture: $arch" ;;
  esac
}

sha256_hex_file() {
  local path="$1"
  if have_cmd sha256sum; then
    sha256sum "$path" | awk '{print $1}'
    return
  fi
  if have_cmd shasum; then
    shasum -a 256 "$path" | awk '{print $1}'
    return
  fi
  die "missing sha256 tool (need sha256sum or shasum)"
}

sha256_hex_stdin() {
  local tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  sha256_hex_file "$tmp"
  rm -f "$tmp"
}

normalize_eth_address() {
  local value
  value="$(trim "$1")"
  if [[ ! "$value" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
    return 1
  fi
  printf '%s' "$(lower "$value")"
}

parse_endpoint_host_port() {
  local endpoint="$1"
  local rest host port

  if [[ ! "$endpoint" =~ ^https:// ]]; then
    return 1
  fi
  rest="${endpoint#https://}"
  if [[ "$rest" == */* ]]; then
    return 1
  fi
  if [[ "$rest" != *:* ]]; then
    return 1
  fi

  host="${rest%:*}"
  port="${rest##*:}"

  if [[ -z "$host" || -z "$port" ]]; then
    return 1
  fi
  if [[ ! "$port" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if (( port < 1 || port > 65535 )); then
    return 1
  fi
  if [[ "$host" =~ [[:space:]/] ]]; then
    return 1
  fi

  printf '%s %s\n' "$host" "$port"
}

ensure_dir() {
  mkdir -p "$1"
}

repair_executable_file() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  if [[ ! -x "$path" ]]; then
    chmod 0755 "$path" 2>/dev/null || chmod u+x "$path" 2>/dev/null || true
  fi
}

remove_macos_quarantine() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  if [[ "$(detect_os)" != "darwin" ]]; then
    return 0
  fi
  if have_cmd xattr; then
    xattr -dr com.apple.quarantine "$path" >/dev/null 2>&1 || true
  fi
}

prepare_execution_path() {
  local path="$1"
  [[ -e "$path" ]] || return 0
  remove_macos_quarantine "$path"
  repair_executable_file "$path"
}

prepare_script_runtime() {
  local script_dir="$1"
  [[ -d "$script_dir" ]] || return 0
  remove_macos_quarantine "$script_dir"
  if [[ -d "$script_dir/bin" ]]; then
    remove_macos_quarantine "$script_dir/bin"
  fi
}

apt_install() {
  if ! have_cmd apt-get; then
    return 1
  fi

  if [[ "$(id -u)" -eq 0 ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  elif have_cmd sudo; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  else
    return 1
  fi
}

install_aws_cli() {
  if have_cmd aws; then
    return 0
  fi

  local arch bundle_name bundle_url workdir
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)
      bundle_name="awscli-exe-linux-x86_64.zip"
      ;;
    aarch64|arm64)
      bundle_name="awscli-exe-linux-aarch64.zip"
      ;;
    *)
      log "unsupported architecture for aws cli install: $arch"
      return 1
      ;;
  esac

  have_cmd unzip || apt_install unzip || return 1

  bundle_url="https://awscli.amazonaws.com/$bundle_name"
  workdir="$(mktemp -d)"
  if ! curl -fsSL "$bundle_url" -o "$workdir/awscliv2.zip"; then
    rm -rf "$workdir"
    return 1
  fi

  (
    set -e
    cd "$workdir"
    unzip -q awscliv2.zip
    if [[ "$(id -u)" -eq 0 ]]; then
      ./aws/install --update
    elif have_cmd sudo; then
      sudo ./aws/install --update
    else
      exit 1
    fi
  ) || {
    rm -rf "$workdir"
    return 1
  }

  rm -rf "$workdir"
  have_cmd aws
}

brew_install_formula() {
  if ! have_cmd brew; then
    log "homebrew not found; installing Homebrew"
    NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || return 1
    if [[ -x /opt/homebrew/bin/brew ]]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -x /usr/local/bin/brew ]]; then
      eval "$(/usr/local/bin/brew shellenv)"
    fi
  fi
  brew list "$1" >/dev/null 2>&1 || brew install "$1"
}

brew_install_cask() {
  if ! have_cmd brew; then
    log "homebrew not found; installing Homebrew"
    NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" || return 1
    if [[ -x /opt/homebrew/bin/brew ]]; then
      eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -x /usr/local/bin/brew ]]; then
      eval "$(/usr/local/bin/brew shellenv)"
    fi
  fi
  brew list --cask "$1" >/dev/null 2>&1 || brew install --cask "$1"
}

ensure_command() {
  local cmd="$1"
  local os
  os="$(detect_os)"

  if have_cmd "$cmd"; then
    return 0
  fi

  log "installing missing dependency: $cmd"
  case "$cmd" in
    jq)
      if [[ "$os" == "darwin" ]]; then
        brew_install_formula jq || die "failed to install jq"
      else
        apt_install jq || die "failed to install jq"
      fi
      ;;
    curl)
      if [[ "$os" == "darwin" ]]; then
        brew_install_formula curl || die "failed to install curl"
      else
        apt_install curl ca-certificates || die "failed to install curl"
      fi
      ;;
    go)
      if [[ "$os" == "darwin" ]]; then
        brew_install_formula go || die "failed to install go"
      else
        apt_install golang-go || die "failed to install go"
      fi
      ;;
    tailscale)
      if [[ "$os" == "darwin" ]]; then
        brew_install_cask tailscale || die "failed to install tailscale"
      else
        if ! apt_install tailscale; then
          curl -fsSL https://tailscale.com/install.sh | sh || die "failed to install tailscale"
        fi
      fi
      ;;
    aws)
      if [[ "$os" == "darwin" ]]; then
        brew_install_formula awscli || die "failed to install awscli"
      else
        if ! apt_install awscli; then
          install_aws_cli || die "failed to install awscli"
        fi
      fi
      ;;
    age|age-keygen)
      if [[ "$os" == "darwin" ]]; then
        brew_install_formula age || die "failed to install age"
      else
        apt_install age || die "failed to install age"
      fi
      ;;
    *)
      die "unsupported auto-install dependency: $cmd"
      ;;
  esac

  have_cmd "$cmd" || die "dependency still missing after install attempt: $cmd"
}

ensure_base_dependencies() {
  ensure_command jq
  ensure_command curl
}

tailscale_status_json() {
  tailscale status --json 2>/dev/null || true
}

is_tailscale_active() {
  if ! have_cmd tailscale; then
    return 1
  fi
  local status backend online
  status="$(tailscale_status_json)"
  [[ -n "$status" ]] || return 1

  backend="$(printf '%s' "$status" | jq -r '.BackendState // ""')"
  online="$(printf '%s' "$status" | jq -r '.Self.Online // false')"
  [[ "$backend" == "Running" && "$online" == "true" ]]
}

dkg_network_mode() {
  local mode="${JUNO_DKG_NETWORK_MODE:-tailscale}"
  mode="$(lower "$(trim "$mode")")"
  case "$mode" in
    tailscale|vpc-private)
      printf '%s' "$mode"
      ;;
    *)
      die "invalid JUNO_DKG_NETWORK_MODE: $mode (expected tailscale or vpc-private)"
      ;;
  esac
}

require_tailscale_active() {
  ensure_base_dependencies
  local network_mode
  network_mode="$(dkg_network_mode)"
  if [[ "$network_mode" == "vpc-private" ]]; then
    return 0
  fi
  if [[ "${JUNO_DKG_ALLOW_INSECURE_NETWORK:-}" == "1" ]]; then
    log "WARNING: JUNO_DKG_ALLOW_INSECURE_NETWORK=1; skipping tailscale activity check"
    return 0
  fi
  if ! is_tailscale_active; then
    die "tailscale is not active; run deploy/operators/dkg/tailscale.sh first"
  fi
}

ensure_tailscale_active() {
  ensure_base_dependencies
  ensure_command tailscale
  if is_tailscale_active; then
    return 0
  fi
  log "bringing tailscale online"
  tailscale up || die "tailscale up failed"
  is_tailscale_active || die "tailscale is still inactive after tailscale up"
}

tailscale_dns_name() {
  require_tailscale_active
  local dns
  dns="$(tailscale status --json | jq -r '.Self.DNSName // ""')"
  dns="${dns%.}"
  [[ -n "$dns" ]] || die "tailscale DNS name not available"
  printf '%s' "$dns"
}

timestamp_utc() {
  date -u +'%Y-%m-%dT%H:%M:%SZ'
}

generate_uuid() {
  if have_cmd uuidgen; then
    lower "$(uuidgen)"
    return
  fi
  if [[ -r /proc/sys/kernel/random/uuid ]]; then
    lower "$(cat /proc/sys/kernel/random/uuid)"
    return
  fi
  die "unable to generate UUID (missing uuidgen)"
}

ensure_operator_keygen_bin() {
  local out_dir="$1"
  local bin="$out_dir/operator-keygen"
  local os arch bundled

  os="$(detect_os)"
  arch="$(detect_arch)"
  bundled="$_SCRIPT_DIR/bin/operator-keygen_${os}_${arch}"
  if [[ -f "$bundled" ]]; then
    prepare_execution_path "$bundled"
    if [[ -x "$bundled" ]]; then
      printf '%s' "$bundled"
      return
    fi
  fi

  if [[ -x "$bin" ]]; then
    prepare_execution_path "$bin"
    printf '%s' "$bin"
    return
  fi

  if [[ ! -f "$REPO_ROOT/go.mod" || ! -f "$REPO_ROOT/cmd/operator-keygen/main.go" ]]; then
    die "operator-keygen not bundled and source build unavailable at $REPO_ROOT"
  fi

  ensure_command go
  ensure_dir "$out_dir"
  (
    cd "$REPO_ROOT"
    go build -o "$bin" ./cmd/operator-keygen
  ) || die "failed to build operator-keygen"
  prepare_execution_path "$bin"
  printf '%s' "$bin"
}

download_file() {
  local url="$1"
  local out="$2"
  curl -fsSL "$url" -o "$out"
}

ensure_dkg_binary() {
  local tool="$1"
  local version="$2"
  local out_dir="$3"
  local env_override=""

  case "$tool" in
    dkg-admin) env_override="${JUNO_DKG_ADMIN_BIN:-}" ;;
    dkg-ceremony) env_override="${JUNO_DKG_CEREMONY_BIN:-}" ;;
    *) die "unsupported dkg binary: $tool" ;;
  esac

  if [[ -n "$env_override" ]]; then
    prepare_execution_path "$env_override"
    [[ -x "$env_override" ]] || die "$tool override is not executable: $env_override"
    printf '%s' "$env_override"
    return
  fi

  ensure_base_dependencies
  local bin_path="$out_dir/$tool"
  if [[ -x "$bin_path" ]]; then
    prepare_execution_path "$bin_path"
    printf '%s' "$bin_path"
    return
  fi

  local os arch asset base_url tmp_dir archive checksum actual expected
  os="$(detect_os)"
  arch="$(detect_arch)"
  asset="${tool}_${version}_${os}_${arch}.tar.gz"
  base_url="https://github.com/junocash-tools/${tool}/releases/download/${version}"

  ensure_dir "$out_dir"
  tmp_dir="$(mktemp -d)"
  archive="$tmp_dir/$asset"
  checksum="$tmp_dir/$asset.sha256"

  if download_file "$base_url/$asset" "$archive"; then
    if download_file "$base_url/$asset.sha256" "$checksum"; then
      expected="$(awk '{print $1}' "$checksum" | head -n1)"
      actual="$(sha256_hex_file "$archive")"
      [[ "$expected" == "$actual" ]] || die "checksum mismatch for $asset"
    else
      log "checksum file unavailable for $asset; proceeding without checksum validation"
    fi
    tar -xzf "$archive" -C "$tmp_dir" || die "failed to extract $asset"
    [[ -f "$tmp_dir/$tool" ]] || die "$tool not present in archive $asset"
    cp "$tmp_dir/$tool" "$bin_path"
    prepare_execution_path "$bin_path"
    rm -rf "$tmp_dir"
    printf '%s' "$bin_path"
    return
  fi
  rm -rf "$tmp_dir"

  log "release asset missing for $tool $version; attempting cargo source build fallback"
  ensure_command go
  ensure_command curl
  ensure_command jq
  if ! have_cmd cargo; then
    curl -fsSL https://sh.rustup.rs | sh -s -- -y || die "failed to install rustup for fallback build"
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
  fi

  local src_root="${JUNO_DKG_SOURCE_ROOT:-$JUNO_DKG_HOME_DEFAULT/src}"
  local src_dir="$src_root/$tool"
  ensure_dir "$src_root"
  if [[ ! -d "$src_dir/.git" ]]; then
    git clone "https://github.com/junocash-tools/${tool}.git" "$src_dir" || die "git clone failed for $tool"
  fi
  (
    cd "$src_dir"
    git fetch origin --tags
    git checkout "$version"
    cargo build --release
  ) || die "cargo build fallback failed for $tool"

  cp "$src_dir/target/release/$tool" "$bin_path"
  prepare_execution_path "$bin_path"
  printf '%s' "$bin_path"
}

ensure_juno_txsign_binary() {
  local version="$1"
  local out_dir="$2"
  local env_override="${JUNO_TXSIGN_BIN:-}"

  if [[ -z "$version" ]]; then
    version="$JUNO_TXSIGN_VERSION_DEFAULT"
  fi

  if [[ -n "$env_override" ]]; then
    prepare_execution_path "$env_override"
    [[ -x "$env_override" ]] || die "juno-txsign override is not executable: $env_override"
    printf '%s' "$env_override"
    return
  fi

  ensure_base_dependencies
  local bin_path="$out_dir/juno-txsign"
  if [[ -x "$bin_path" ]]; then
    prepare_execution_path "$bin_path"
    printf '%s' "$bin_path"
    return
  fi

  local os arch asset base_url tmp_dir archive checksum actual expected
  os="$(detect_os)"
  arch="$(detect_arch)"
  asset="juno-txsign_${version}_${os}_${arch}.tar.gz"
  base_url="https://github.com/junocash-tools/juno-txsign/releases/download/${version}"

  ensure_dir "$out_dir"
  tmp_dir="$(mktemp -d)"
  archive="$tmp_dir/$asset"
  checksum="$tmp_dir/$asset.sha256"

  if download_file "$base_url/$asset" "$archive"; then
    if download_file "$base_url/$asset.sha256" "$checksum"; then
      expected="$(awk '{print $1}' "$checksum" | head -n1)"
      actual="$(sha256_hex_file "$archive")"
      [[ "$expected" == "$actual" ]] || die "checksum mismatch for $asset"
    else
      log "checksum file unavailable for $asset; proceeding without checksum validation"
    fi
    tar -xzf "$archive" -C "$tmp_dir" || die "failed to extract $asset"
    [[ -f "$tmp_dir/juno-txsign" ]] || die "juno-txsign not present in archive $asset"
    cp "$tmp_dir/juno-txsign" "$bin_path"
    prepare_execution_path "$bin_path"
    rm -rf "$tmp_dir"
    printf '%s' "$bin_path"
    return
  fi
  rm -rf "$tmp_dir"

  log "release asset missing for juno-txsign $version; attempting cargo source build fallback"
  ensure_command curl
  ensure_command jq
  if ! have_cmd cargo; then
    curl -fsSL https://sh.rustup.rs | sh -s -- -y || die "failed to install rustup for fallback build"
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
  fi

  local src_root="${JUNO_DKG_SOURCE_ROOT:-$JUNO_DKG_HOME_DEFAULT/src}"
  local src_dir="$src_root/juno-txsign"
  ensure_dir "$src_root"
  if [[ ! -d "$src_dir/.git" ]]; then
    git clone "https://github.com/junocash-tools/juno-txsign.git" "$src_dir" || die "git clone failed for juno-txsign"
  fi
  (
    cd "$src_dir"
    git fetch origin --tags
    git checkout "$version"
    cargo build --release
  ) || die "cargo build fallback failed for juno-txsign"

  cp "$src_dir/target/release/juno-txsign" "$bin_path"
  prepare_execution_path "$bin_path"
  printf '%s' "$bin_path"
}
