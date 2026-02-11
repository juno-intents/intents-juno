#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

JUNO_DKG_VERSION_DEFAULT="${JUNO_DKG_VERSION_DEFAULT:-v0.1.0}"
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

detect_os() {
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

require_tailscale_active() {
  ensure_base_dependencies
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
    chmod 0755 "$bundled" || true
    if [[ -x "$bundled" ]]; then
      printf '%s' "$bundled"
      return
    fi
  fi

  if [[ -x "$bin" ]]; then
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
  chmod 0755 "$bin"
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
    [[ -x "$env_override" ]] || die "$tool override is not executable: $env_override"
    printf '%s' "$env_override"
    return
  fi

  ensure_base_dependencies
  local bin_path="$out_dir/$tool"
  if [[ -x "$bin_path" ]]; then
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
    chmod 0755 "$bin_path"
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
  chmod 0755 "$bin_path"
  printf '%s' "$bin_path"
}
