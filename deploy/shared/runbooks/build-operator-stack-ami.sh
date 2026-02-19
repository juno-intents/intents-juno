#!/usr/bin/env bash
# shellcheck shell=bash

set -euo pipefail

cleanup_enabled="false"
cleanup_keep_builder="false"
cleanup_key_name=""
cleanup_key_dir=""
cleanup_security_group_id=""
cleanup_instance_id=""
cleanup_aws_profile=""
cleanup_aws_region=""

usage() {
  cat <<'HELP'
Usage:
  build-operator-stack-ami.sh create [options]

Options:
  --aws-region <region>            AWS region (required)
  --aws-profile <name>             optional AWS profile
  --instance-type <type>           builder EC2 instance type (default: c7i.4xlarge)
  --name-prefix <prefix>           image/resource name prefix (default: intents-juno-operator-stack)
  --repo-url <url>                 intents-juno repo URL (default: https://github.com/juno-intents/intents-juno.git)
  --repo-commit <sha>              intents-juno commit to bake (default: local git HEAD or $GITHUB_SHA)
  --base-chain-id <id>             Base chain id for standby checkpoint stack (default: 84532)
  --bridge-address <address>       Bridge address for standby checkpoint stack
                                   (default: 0x0000000000000000000000000000000000000000)
  --sync-timeout-seconds <n>       max seconds to wait for junocashd sync (default: 21600)
  --source-ami-id <ami-id>         optional base AMI id for builder (default: latest Ubuntu 24.04 amd64)
  --vpc-id <vpc-id>                optional VPC id (default: default VPC)
  --subnet-id <subnet-id>          optional subnet id (default: first available subnet in VPC)
  --ssh-allowed-cidr <cidr>        optional SSH CIDR allowlist (default: caller public IP /32)
  --image-name <name>              optional final AMI name (default: <prefix>-h<height>-<timestamp>)
  --image-description <text>       optional AMI description
  --manifest-out <path>            manifest output path (default: ./operator-ami-manifest.json)
  --metadata-out <path>            bootstrap metadata output path (default: ./operator-stack-bootstrap.json)
  --keep-builder-instance          keep temporary builder EC2 instance for debugging

Example:
  ./deploy/shared/runbooks/build-operator-stack-ami.sh create \
    --aws-region us-east-1 \
    --repo-commit "$(git rev-parse HEAD)" \
    --manifest-out .ci/out/operator-ami-manifest.json \
    --metadata-out .ci/out/operator-stack-bootstrap.json
HELP
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"
}

ensure_cmd() {
  local cmd="$1"
  have_cmd "$cmd" || die "missing required command: $cmd"
}

aws_args() {
  local profile="$1"
  local region="$2"
  AWS_ARGS=()
  if [[ -n "$profile" ]]; then
    AWS_ARGS+=(--profile "$profile")
  fi
  if [[ -n "$region" ]]; then
    AWS_ARGS+=(--region "$region")
  fi
}

aws_cli() {
  AWS_PAGER="" aws "${AWS_ARGS[@]}" "$@"
}

cleanup_trap() {
  if [[ "$cleanup_enabled" != "true" ]]; then
    return 0
  fi

  aws_args "$cleanup_aws_profile" "$cleanup_aws_region"

  if [[ "$cleanup_keep_builder" != "true" && -n "$cleanup_instance_id" ]]; then
    log "cleanup: terminating builder instance $cleanup_instance_id"
    aws_cli ec2 terminate-instances --instance-ids "$cleanup_instance_id" >/dev/null 2>&1 || true
    aws_cli ec2 wait instance-terminated --instance-ids "$cleanup_instance_id" >/dev/null 2>&1 || true
  fi

  if [[ -n "$cleanup_security_group_id" ]]; then
    if [[ "$cleanup_keep_builder" == "true" ]]; then
      log "cleanup: keeping security group $cleanup_security_group_id because --keep-builder-instance is set"
    else
      log "cleanup: deleting security group $cleanup_security_group_id"
      aws_cli ec2 delete-security-group --group-id "$cleanup_security_group_id" >/dev/null 2>&1 || true
    fi
  fi

  if [[ -n "$cleanup_key_name" ]]; then
    if [[ "$cleanup_keep_builder" == "true" ]]; then
      log "cleanup: keeping key pair $cleanup_key_name because --keep-builder-instance is set"
    else
      log "cleanup: deleting key pair $cleanup_key_name"
      aws_cli ec2 delete-key-pair --key-name "$cleanup_key_name" >/dev/null 2>&1 || true
    fi
  fi

  if [[ -n "$cleanup_key_dir" && -d "$cleanup_key_dir" ]]; then
    rm -rf "$cleanup_key_dir"
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
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
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

build_remote_bootstrap_script() {
  local repo_url="$1"
  local repo_commit="$2"
  local base_chain_id="$3"
  local bridge_address="$4"
  local sync_timeout_seconds="$5"

  cat <<REMOTE_SCRIPT
#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

run_with_retry() {
  local attempt
  for attempt in \$(seq 1 30); do
    if "\$@"; then
      return 0
    fi
    sleep 5
  done
  return 1
}

install_junocash() {
  local release_json release_tag asset_url archive root_dir
  release_json="\$(curl -fsSL https://api.github.com/repos/juno-cash/junocash/releases/latest)"
  release_tag="\$(jq -r '.tag_name // empty' <<<"\$release_json")"
  asset_url="\$(jq -r '.assets[] | select((.name | endswith("linux64.tar.gz")) and (.name | contains("debug") | not)) | .browser_download_url' <<<"\$release_json" | head -n 1)"
  [[ -n "\$release_tag" ]] || { echo "failed to resolve junocash release tag" >&2; return 1; }
  [[ -n "\$asset_url" ]] || { echo "failed to resolve junocash linux asset" >&2; return 1; }

  archive="\$(mktemp)"
  curl -fsSL "\$asset_url" -o "\$archive"
  tar -xzf "\$archive" -C /tmp
  rm -f "\$archive"

  root_dir="\$(find /tmp -maxdepth 1 -type d -name 'junocash-*' | head -n 1)"
  [[ -n "\$root_dir" ]] || { echo "junocash archive extraction failed" >&2; return 1; }

  sudo install -m 0755 "\$root_dir/bin/junocashd" /usr/local/bin/junocashd
  sudo install -m 0755 "\$root_dir/bin/junocash-cli" /usr/local/bin/junocash-cli

  echo "\$release_tag" > "\$HOME/.junocash-release-tag"
}

install_juno_scan() {
  local release_json release_tag asset_url archive
  release_json="\$(curl -fsSL https://api.github.com/repos/junocash-tools/juno-scan/releases/latest)"
  release_tag="\$(jq -r '.tag_name // empty' <<<"\$release_json")"
  asset_url="\$(jq -r '.assets[] | select(.name | endswith("linux_amd64.tar.gz")) | .browser_download_url' <<<"\$release_json" | head -n 1)"
  [[ -n "\$release_tag" ]] || { echo "failed to resolve juno-scan release tag" >&2; return 1; }
  [[ -n "\$asset_url" ]] || { echo "failed to resolve juno-scan linux asset" >&2; return 1; }

  archive="\$(mktemp)"
  curl -fsSL "\$asset_url" -o "\$archive"
  tar -xzf "\$archive" -C /tmp
  rm -f "\$archive"

  [[ -x /tmp/juno-scan ]] || { echo "juno-scan archive extraction failed" >&2; return 1; }
  sudo install -m 0755 /tmp/juno-scan /usr/local/bin/juno-scan

  echo "\$release_tag" > "\$HOME/.juno-scan-release-tag"
}

install_intents_binaries() {
  local repo_dir="\$HOME/intents-juno"
  if [[ ! -d "\$repo_dir/.git" ]]; then
    git clone "${repo_url}" "\$repo_dir"
  fi
  cd "\$repo_dir"
  git fetch --tags origin
  git checkout "${repo_commit}"

  local out_dir
  out_dir="\$(mktemp -d)"
  go build -o "\$out_dir/operator-keygen" ./cmd/operator-keygen
  go build -o "\$out_dir/checkpoint-signer" ./cmd/checkpoint-signer
  go build -o "\$out_dir/checkpoint-aggregator" ./cmd/checkpoint-aggregator
  go build -o "\$out_dir/tss-host" ./cmd/tss-host
  go build -o "\$out_dir/tss-signer" ./cmd/tss-signer

  sudo install -m 0755 "\$out_dir/operator-keygen" /usr/local/bin/operator-keygen
  sudo install -m 0755 "\$out_dir/checkpoint-signer" /usr/local/bin/checkpoint-signer
  sudo install -m 0755 "\$out_dir/checkpoint-aggregator" /usr/local/bin/checkpoint-aggregator
  sudo install -m 0755 "\$out_dir/tss-host" /usr/local/bin/tss-host
  sudo install -m 0755 "\$out_dir/tss-signer" /usr/local/bin/tss-signer
}

write_stack_config() {
  local rpc_user rpc_pass checkpoint_key operator_address
  rpc_user="juno"
  rpc_pass="\$(openssl rand -hex 16)"

  sudo mkdir -p /etc/intents-juno
  sudo mkdir -p /var/lib/intents-juno/junocashd /var/lib/intents-juno/juno-scan /var/lib/intents-juno/operator-runtime /var/lib/intents-juno/tss-signer
  sudo chown -R ubuntu:ubuntu /var/lib/intents-juno

  cat > /tmp/junocashd.conf <<CFG
 testnet=1
 server=1
 txindex=1
 daemon=0
 listen=1
 rpcbind=127.0.0.1
 rpcallowip=127.0.0.1
 rpcport=18232
 rpcuser=\${rpc_user}
 rpcpassword=\${rpc_pass}
CFG
  sudo install -m 0600 /tmp/junocashd.conf /etc/intents-juno/junocashd.conf

  sudo /usr/local/bin/operator-keygen --private-key-path /etc/intents-juno/checkpoint-signer.key >/tmp/operator-meta.json
  operator_address="\$(jq -r '.operator_id // empty' /tmp/operator-meta.json)"
  [[ -n "\$operator_address" ]] || { echo "failed to resolve operator address" >&2; return 1; }
  checkpoint_key="\$(tr -d '\r\n' < /etc/intents-juno/checkpoint-signer.key)"
  [[ -n "\$checkpoint_key" ]] || { echo "failed to load checkpoint signer key" >&2; return 1; }

  cat > /tmp/operator-stack.env <<ENV
JUNO_RPC_USER=\${rpc_user}
JUNO_RPC_PASS=\${rpc_pass}
CHECKPOINT_SIGNER_PRIVATE_KEY=\${checkpoint_key}
OPERATOR_ADDRESS=\${operator_address}
CHECKPOINT_OPERATORS=\${operator_address}
CHECKPOINT_THRESHOLD=1
CHECKPOINT_POSTGRES_DSN=
CHECKPOINT_KAFKA_BROKERS=
CHECKPOINT_SIGNATURE_TOPIC=checkpoints.signatures.v1
CHECKPOINT_PACKAGE_TOPIC=checkpoints.packages.v1
CHECKPOINT_BLOB_BUCKET=
CHECKPOINT_BLOB_PREFIX=checkpoint-packages
CHECKPOINT_IPFS_API_URL=
TSS_SIGNER_UFVK_FILE=/var/lib/intents-juno/operator-runtime/ufvk.txt
TSS_SPENDAUTH_SIGNER_BIN=/var/lib/intents-juno/operator-runtime/bin/dkg-admin
TSS_SIGNER_WORK_DIR=/var/lib/intents-juno/tss-signer
ENV
  sudo install -m 0600 /tmp/operator-stack.env /etc/intents-juno/operator-stack.env

  cat > /tmp/intents-juno-juno-scan.sh <<'EOF_SCAN'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env
exec /usr/local/bin/juno-scan \
  -rpc-url http://127.0.0.1:18232 \
  -rpc-user "\$JUNO_RPC_USER" \
  -rpc-pass "\$JUNO_RPC_PASS" \
  -db-driver rocksdb \
  -db-path /var/lib/intents-juno/juno-scan.db \
  -listen 127.0.0.1:8080
EOF_SCAN
  sudo install -m 0755 /tmp/intents-juno-juno-scan.sh /usr/local/bin/intents-juno-juno-scan.sh

  cat > /tmp/intents-juno-checkpoint-signer.sh <<'EOF_SIGNER'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env
[[ -n "\${CHECKPOINT_POSTGRES_DSN:-}" ]] || {
  echo "checkpoint-signer requires CHECKPOINT_POSTGRES_DSN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "\${CHECKPOINT_KAFKA_BROKERS:-}" ]] || {
  echo "checkpoint-signer requires CHECKPOINT_KAFKA_BROKERS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "\${CHECKPOINT_SIGNATURE_TOPIC:-}" ]] || {
  echo "checkpoint-signer requires CHECKPOINT_SIGNATURE_TOPIC in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "\${CHECKPOINT_THRESHOLD:-}" ]] || {
  echo "checkpoint-signer requires CHECKPOINT_THRESHOLD in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
exec /usr/local/bin/checkpoint-signer \
  --juno-rpc-url http://127.0.0.1:18232 \
  --base-chain-id __BASE_CHAIN_ID__ \
  --bridge-address __BRIDGE_ADDRESS__ \
  --confirmations 1 \
  --poll-interval 15s \
  --owner-id "\$(hostname -s)" \
  --postgres-dsn "\$CHECKPOINT_POSTGRES_DSN" \
  --lease-driver postgres \
  --queue-driver kafka \
  --queue-brokers "\$CHECKPOINT_KAFKA_BROKERS" \
  --queue-output-topic "\$CHECKPOINT_SIGNATURE_TOPIC"
EOF_SIGNER
  sed -i "s/__BASE_CHAIN_ID__/${base_chain_id}/g; s/__BRIDGE_ADDRESS__/${bridge_address}/g" /tmp/intents-juno-checkpoint-signer.sh
  sudo install -m 0755 /tmp/intents-juno-checkpoint-signer.sh /usr/local/bin/intents-juno-checkpoint-signer.sh

  cat > /tmp/intents-juno-checkpoint-aggregator.sh <<'EOF_AGG'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env
[[ -n "\${CHECKPOINT_POSTGRES_DSN:-}" ]] || {
  echo "checkpoint-aggregator requires CHECKPOINT_POSTGRES_DSN in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "\${CHECKPOINT_KAFKA_BROKERS:-}" ]] || {
  echo "checkpoint-aggregator requires CHECKPOINT_KAFKA_BROKERS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "\${CHECKPOINT_BLOB_BUCKET:-}" ]] || {
  echo "checkpoint-aggregator requires CHECKPOINT_BLOB_BUCKET in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "\${CHECKPOINT_IPFS_API_URL:-}" ]] || {
  echo "checkpoint-aggregator requires CHECKPOINT_IPFS_API_URL in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "\${CHECKPOINT_OPERATORS:-}" ]] || {
  echo "checkpoint-aggregator requires CHECKPOINT_OPERATORS in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
[[ -n "\${CHECKPOINT_THRESHOLD:-}" ]] || {
  echo "checkpoint-aggregator requires CHECKPOINT_THRESHOLD in /etc/intents-juno/operator-stack.env" >&2
  exit 1
}
exec /usr/local/bin/checkpoint-aggregator \
  --base-chain-id __BASE_CHAIN_ID__ \
  --bridge-address __BRIDGE_ADDRESS__ \
  --operators "\$CHECKPOINT_OPERATORS" \
  --threshold "\$CHECKPOINT_THRESHOLD" \
  --store-driver postgres \
  --postgres-dsn "\$CHECKPOINT_POSTGRES_DSN" \
  --blob-driver s3 \
  --blob-bucket "\$CHECKPOINT_BLOB_BUCKET" \
  --blob-prefix "\${CHECKPOINT_BLOB_PREFIX:-checkpoint-packages}" \
  --ipfs-enabled=true \
  --ipfs-api-url "\$CHECKPOINT_IPFS_API_URL" \
  --queue-driver kafka \
  --queue-brokers "\$CHECKPOINT_KAFKA_BROKERS" \
  --queue-input-topics "\${CHECKPOINT_SIGNATURE_TOPIC:-checkpoints.signatures.v1}" \
  --queue-output-topic "\${CHECKPOINT_PACKAGE_TOPIC:-checkpoints.packages.v1}"
EOF_AGG
  sed -i "s/__BASE_CHAIN_ID__/${base_chain_id}/g; s/__BRIDGE_ADDRESS__/${bridge_address}/g" /tmp/intents-juno-checkpoint-aggregator.sh
  sudo install -m 0755 /tmp/intents-juno-checkpoint-aggregator.sh /usr/local/bin/intents-juno-checkpoint-aggregator.sh

  cat > /tmp/intents-juno-tss-host.sh <<'EOF_TSS'
#!/usr/bin/env bash
set -euo pipefail
# shellcheck disable=SC1091
source /etc/intents-juno/operator-stack.env
[[ -s "${TSS_SIGNER_UFVK_FILE:-}" ]] || {
  echo "tss-host signer UFVK file is missing or empty: ${TSS_SIGNER_UFVK_FILE:-unset}" >&2
  exit 1
}
[[ -x "${TSS_SPENDAUTH_SIGNER_BIN:-}" ]] || {
  echo "tss-host spendauth signer binary is missing or not executable: ${TSS_SPENDAUTH_SIGNER_BIN:-unset}" >&2
  exit 1
}
[[ -n "${TSS_SIGNER_WORK_DIR:-}" ]] || {
  echo "tss-host signer work directory is not configured (TSS_SIGNER_WORK_DIR)" >&2
  exit 1
}
mkdir -p "${TSS_SIGNER_WORK_DIR}"
exec /usr/local/bin/tss-host \
  --listen-addr 127.0.0.1:9443 \
  --insecure-http \
  --signer-bin /usr/local/bin/tss-signer \
  --signer-arg --ufvk-file \
  --signer-arg "${TSS_SIGNER_UFVK_FILE}" \
  --signer-arg --spendauth-signer-bin \
  --signer-arg "${TSS_SPENDAUTH_SIGNER_BIN}" \
  --signer-arg --work-dir \
  --signer-arg "${TSS_SIGNER_WORK_DIR}"
EOF_TSS
  sudo install -m 0755 /tmp/intents-juno-tss-host.sh /usr/local/bin/intents-juno-tss-host.sh

  cat > /tmp/junocashd.service <<'EOF_JUNOD'
[Unit]
Description=Intents Juno Operator junocashd
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
ExecStart=/usr/local/bin/junocashd -conf=/etc/intents-juno/junocashd.conf -datadir=/var/lib/intents-juno/junocashd
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF_JUNOD
  sudo install -m 0644 /tmp/junocashd.service /etc/systemd/system/junocashd.service

  cat > /tmp/juno-scan.service <<'EOF_SCAN_SERVICE'
[Unit]
Description=Intents Juno Operator juno-scan
After=junocashd.service
Requires=junocashd.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
ExecStart=/usr/local/bin/intents-juno-juno-scan.sh
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF_SCAN_SERVICE
  sudo install -m 0644 /tmp/juno-scan.service /etc/systemd/system/juno-scan.service

  cat > /tmp/checkpoint-signer.service <<'EOF_SIGNER_SERVICE'
[Unit]
Description=Intents Juno Operator checkpoint-signer
After=junocashd.service
Requires=junocashd.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
ExecStart=/usr/local/bin/intents-juno-checkpoint-signer.sh
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF_SIGNER_SERVICE
  sudo install -m 0644 /tmp/checkpoint-signer.service /etc/systemd/system/checkpoint-signer.service

  cat > /tmp/checkpoint-aggregator.service <<'EOF_AGG_SERVICE'
[Unit]
Description=Intents Juno Operator checkpoint-aggregator
After=checkpoint-signer.service
Requires=checkpoint-signer.service

[Service]
Type=simple
User=ubuntu
Group=ubuntu
ExecStart=/usr/local/bin/intents-juno-checkpoint-aggregator.sh
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF_AGG_SERVICE
  sudo install -m 0644 /tmp/checkpoint-aggregator.service /etc/systemd/system/checkpoint-aggregator.service

  cat > /tmp/tss-host.service <<'EOF_TSS_SERVICE'
[Unit]
Description=Intents Juno Operator tss-host
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
ExecStart=/usr/local/bin/intents-juno-tss-host.sh
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF_TSS_SERVICE
  sudo install -m 0644 /tmp/tss-host.service /etc/systemd/system/tss-host.service
}

wait_for_sync_and_record_blockstamp() {
  local rpc_user rpc_pass rpc_args info blocks headers progress block_hash now sync_deadline
  rpc_user="\$(grep '^JUNO_RPC_USER=' /etc/intents-juno/operator-stack.env | cut -d= -f2-)"
  rpc_pass="\$(grep '^JUNO_RPC_PASS=' /etc/intents-juno/operator-stack.env | cut -d= -f2-)"
  rpc_args=(-testnet -rpcconnect=127.0.0.1 -rpcport=18232 -rpcuser="\$rpc_user" -rpcpassword="\$rpc_pass")

  sync_deadline=\$(( \$(date +%s) + ${sync_timeout_seconds} ))

  for _ in \$(seq 1 180); do
    if /usr/local/bin/junocash-cli "\${rpc_args[@]}" getblockchaininfo >/tmp/blockchaininfo.json 2>/dev/null; then
      break
    fi
    sleep 5
  done

  while true; do
    now=\$(date +%s)
    if (( now >= sync_deadline )); then
      echo "timed out waiting for junocashd sync" >&2
      return 1
    fi

    if ! info="\$(/usr/local/bin/junocash-cli "\${rpc_args[@]}" getblockchaininfo 2>/dev/null)"; then
      sleep 10
      continue
    fi

    blocks="\$(jq -r '.blocks // 0' <<<"\$info")"
    headers="\$(jq -r '.headers // 0' <<<"\$info")"
    progress="\$(jq -r '.verificationprogress // 0' <<<"\$info")"

    if [[ "\$blocks" =~ ^[0-9]+$ ]] && [[ "\$headers" =~ ^[0-9]+$ ]]; then
      if (( blocks + 1 >= headers )) && awk -v p="\$progress" 'BEGIN { exit (p >= 0.999 ? 0 : 1) }'; then
        block_hash="\$(/usr/local/bin/junocash-cli "\${rpc_args[@]}" getbestblockhash)"
        cat > "\$HOME/.junocash-blockstamp" <<STAMP
\${blocks}
\${block_hash}
STAMP
        return 0
      fi
    fi

    sleep 15
  done
}

write_bootstrap_metadata() {
  local juno_release_tag juno_scan_release_tag block_height block_hash
  juno_release_tag="\$(cat "\$HOME/.junocash-release-tag")"
  juno_scan_release_tag="\$(cat "\$HOME/.juno-scan-release-tag")"
  block_height="\$(sed -n '1p' "\$HOME/.junocash-blockstamp")"
  block_hash="\$(sed -n '2p' "\$HOME/.junocash-blockstamp")"

  jq -n \
    --arg generated_at "\$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg repo_url "${repo_url}" \
    --arg repo_commit "${repo_commit}" \
    --arg junocash_release_tag "\$juno_release_tag" \
    --arg juno_scan_release_tag "\$juno_scan_release_tag" \
    --argjson synced_block_height "\$block_height" \
    --arg synced_block_hash "\$block_hash" \
    --arg operator_address "\$(jq -r '.operator_id // empty' /tmp/operator-meta.json)" \
    '{
      generated_at: \$generated_at,
      repo: {
        url: \$repo_url,
        commit: \$repo_commit
      },
      junocashd: {
        release_tag: \$junocash_release_tag,
        synced_block_height: \$synced_block_height,
        synced_block_hash: \$synced_block_hash
      },
      juno_scan: {
        release_tag: \$juno_scan_release_tag
      },
      operator: {
        operator_id: \$operator_address
      },
      services: [
        "junocashd.service",
        "juno-scan.service",
        "checkpoint-signer.service",
        "checkpoint-aggregator.service",
        "tss-host.service"
      ]
    }' > "\$HOME/operator-stack-bootstrap.json"
}

run_with_retry sudo apt-get update -y
run_with_retry sudo apt-get install -y ca-certificates curl jq tar git golang-go build-essential make openssl

install_junocash
install_juno_scan
install_intents_binaries
write_stack_config

sudo systemctl daemon-reload
sudo systemctl enable junocashd.service juno-scan.service checkpoint-signer.service checkpoint-aggregator.service tss-host.service
sudo systemctl restart junocashd.service juno-scan.service

wait_for_sync_and_record_blockstamp

for svc in junocashd.service juno-scan.service; do
  sudo systemctl is-active --quiet "\$svc"
done

write_bootstrap_metadata

sudo systemctl stop juno-scan.service checkpoint-signer.service checkpoint-aggregator.service tss-host.service || true
rpc_user="\$(grep '^JUNO_RPC_USER=' /etc/intents-juno/operator-stack.env | cut -d= -f2-)"
rpc_pass="\$(grep '^JUNO_RPC_PASS=' /etc/intents-juno/operator-stack.env | cut -d= -f2-)"
/usr/local/bin/junocash-cli -testnet -rpcconnect=127.0.0.1 -rpcport=18232 -rpcuser="\$rpc_user" -rpcpassword="\$rpc_pass" stop >/dev/null 2>&1 || true
for _ in \$(seq 1 60); do
  if ! pgrep -x junocashd >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
sync
REMOTE_SCRIPT
}

command_create() {
  shift || true

  local aws_region=""
  local aws_profile=""
  local instance_type="c7i.4xlarge"
  local name_prefix="intents-juno-operator-stack"
  local repo_url="https://github.com/juno-intents/intents-juno.git"
  local repo_commit=""
  local base_chain_id="84532"
  local bridge_address="0x0000000000000000000000000000000000000000"
  local sync_timeout_seconds="21600"
  local source_ami_id=""
  local vpc_id=""
  local subnet_id=""
  local ssh_allowed_cidr=""
  local image_name=""
  local image_description=""
  local manifest_out="./operator-ami-manifest.json"
  local metadata_out="./operator-stack-bootstrap.json"
  local keep_builder_instance="false"

  while [[ $# -gt 0 ]]; do
    case "$1" in
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
      --instance-type)
        [[ $# -ge 2 ]] || die "missing value for --instance-type"
        instance_type="$2"
        shift 2
        ;;
      --name-prefix)
        [[ $# -ge 2 ]] || die "missing value for --name-prefix"
        name_prefix="$2"
        shift 2
        ;;
      --repo-url)
        [[ $# -ge 2 ]] || die "missing value for --repo-url"
        repo_url="$2"
        shift 2
        ;;
      --repo-commit)
        [[ $# -ge 2 ]] || die "missing value for --repo-commit"
        repo_commit="$2"
        shift 2
        ;;
      --base-chain-id)
        [[ $# -ge 2 ]] || die "missing value for --base-chain-id"
        base_chain_id="$2"
        shift 2
        ;;
      --bridge-address)
        [[ $# -ge 2 ]] || die "missing value for --bridge-address"
        bridge_address="$2"
        shift 2
        ;;
      --sync-timeout-seconds)
        [[ $# -ge 2 ]] || die "missing value for --sync-timeout-seconds"
        sync_timeout_seconds="$2"
        shift 2
        ;;
      --source-ami-id)
        [[ $# -ge 2 ]] || die "missing value for --source-ami-id"
        source_ami_id="$2"
        shift 2
        ;;
      --vpc-id)
        [[ $# -ge 2 ]] || die "missing value for --vpc-id"
        vpc_id="$2"
        shift 2
        ;;
      --subnet-id)
        [[ $# -ge 2 ]] || die "missing value for --subnet-id"
        subnet_id="$2"
        shift 2
        ;;
      --ssh-allowed-cidr)
        [[ $# -ge 2 ]] || die "missing value for --ssh-allowed-cidr"
        ssh_allowed_cidr="$2"
        shift 2
        ;;
      --image-name)
        [[ $# -ge 2 ]] || die "missing value for --image-name"
        image_name="$2"
        shift 2
        ;;
      --image-description)
        [[ $# -ge 2 ]] || die "missing value for --image-description"
        image_description="$2"
        shift 2
        ;;
      --manifest-out)
        [[ $# -ge 2 ]] || die "missing value for --manifest-out"
        manifest_out="$2"
        shift 2
        ;;
      --metadata-out)
        [[ $# -ge 2 ]] || die "missing value for --metadata-out"
        metadata_out="$2"
        shift 2
        ;;
      --keep-builder-instance)
        keep_builder_instance="true"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown argument for create: $1"
        ;;
    esac
  done

  [[ -n "$aws_region" ]] || die "--aws-region is required"
  [[ "$sync_timeout_seconds" =~ ^[0-9]+$ ]] || die "--sync-timeout-seconds must be numeric"
  (( sync_timeout_seconds > 0 )) || die "--sync-timeout-seconds must be > 0"
  [[ "$base_chain_id" =~ ^[0-9]+$ ]] || die "--base-chain-id must be numeric"
  [[ "$bridge_address" =~ ^0x[0-9a-fA-F]{40}$ ]] || die "--bridge-address must be a 20-byte hex address"
  if [[ -n "$source_ami_id" && ! "$source_ami_id" =~ ^ami-[a-zA-Z0-9]+$ ]]; then
    die "--source-ami-id must look like an AMI id (ami-...)"
  fi
  if [[ -z "$repo_commit" ]]; then
    if [[ -n "${GITHUB_SHA:-}" ]]; then
      repo_commit="$GITHUB_SHA"
    elif git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      repo_commit="$(git rev-parse HEAD)"
    else
      die "--repo-commit is required when not running from git checkout"
    fi
  fi

  ensure_cmd aws
  ensure_cmd ssh
  ensure_cmd scp
  ensure_cmd jq
  ensure_cmd curl
  ensure_cmd ssh-keygen
  ensure_cmd openssl

  aws_args "$aws_profile" "$aws_region"

  cleanup_enabled="true"
  cleanup_keep_builder="$keep_builder_instance"
  cleanup_aws_profile="$aws_profile"
  cleanup_aws_region="$aws_region"
  trap cleanup_trap EXIT

  if [[ -z "$ssh_allowed_cidr" ]]; then
    local caller_ip
    caller_ip="$(curl -fsS https://checkip.amazonaws.com | tr -d '\r\n')"
    [[ "$caller_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "failed to detect caller IP for SSH allowlist"
    ssh_allowed_cidr="${caller_ip}/32"
  fi

  if [[ -z "$vpc_id" ]]; then
    vpc_id="$(aws_cli ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)"
    [[ -n "$vpc_id" && "$vpc_id" != "None" ]] || die "failed to resolve default VPC; pass --vpc-id"
  fi

  if [[ -z "$subnet_id" ]]; then
    subnet_id="$(
      aws_cli ec2 describe-subnets \
        --filters Name=vpc-id,Values="$vpc_id" Name=state,Values=available \
        --query 'Subnets[0].SubnetId' \
        --output text
    )"
    [[ -n "$subnet_id" && "$subnet_id" != "None" ]] || die "failed to resolve subnet in VPC $vpc_id; pass --subnet-id"
  fi

  if [[ -z "$source_ami_id" ]]; then
    source_ami_id="$(
      aws_cli ec2 describe-images \
        --owners 099720109477 \
        --filters \
          Name=name,Values='ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*' \
          Name=state,Values=available \
          Name=virtualization-type,Values=hvm \
        --query 'sort_by(Images,&CreationDate)[-1].ImageId' \
        --output text
    )"
    [[ -n "$source_ami_id" && "$source_ami_id" != "None" ]] || die "failed to resolve Ubuntu base AMI"
  fi

  local timestamp suffix key_name sg_name key_dir ssh_private_key ssh_public_key
  timestamp="$(date -u +%Y%m%d%H%M%S)"
  suffix="$(openssl rand -hex 3)"
  key_name="${name_prefix}-key-${timestamp}-${suffix}"
  sg_name="${name_prefix}-sg-${timestamp}-${suffix}"

  key_dir="$(mktemp -d)"
  ssh_private_key="$key_dir/id_ed25519"
  ssh_public_key="$ssh_private_key.pub"
  ssh-keygen -t ed25519 -N "" -f "$ssh_private_key" >/dev/null

  cleanup_key_dir="$key_dir"
  cleanup_key_name="$key_name"

  log "importing temporary EC2 key pair $key_name"
  aws_cli ec2 import-key-pair --key-name "$key_name" --public-key-material "fileb://$ssh_public_key" >/dev/null

  log "creating temporary security group $sg_name in VPC $vpc_id"
  cleanup_security_group_id="$(
    aws_cli ec2 create-security-group \
      --group-name "$sg_name" \
      --description "intents-juno operator AMI builder SSH group" \
      --vpc-id "$vpc_id" \
      --query 'GroupId' \
      --output text
  )"
  [[ -n "$cleanup_security_group_id" && "$cleanup_security_group_id" != "None" ]] || die "failed to create temporary security group"

  aws_cli ec2 authorize-security-group-ingress \
    --group-id "$cleanup_security_group_id" \
    --protocol tcp \
    --port 22 \
    --cidr "$ssh_allowed_cidr" >/dev/null

  log "launching temporary builder instance"
  cleanup_instance_id="$(
    aws_cli ec2 run-instances \
      --image-id "$source_ami_id" \
      --instance-type "$instance_type" \
      --key-name "$key_name" \
      --security-group-ids "$cleanup_security_group_id" \
      --subnet-id "$subnet_id" \
      --associate-public-ip-address \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${name_prefix}-builder},{Key=Project,Value=intents-juno},{Key=Stack,Value=operator-ami-builder}]" \
      --query 'Instances[0].InstanceId' \
      --output text
  )"
  [[ -n "$cleanup_instance_id" && "$cleanup_instance_id" != "None" ]] || die "failed to launch builder instance"

  aws_cli ec2 wait instance-running --instance-ids "$cleanup_instance_id"

  local builder_public_ip builder_user
  builder_public_ip="$(
    aws_cli ec2 describe-instances \
      --instance-ids "$cleanup_instance_id" \
      --query 'Reservations[0].Instances[0].PublicIpAddress' \
      --output text
  )"
  [[ -n "$builder_public_ip" && "$builder_public_ip" != "None" ]] || die "builder instance has no public IP"
  builder_user="ubuntu"

  wait_for_ssh "$ssh_private_key" "$builder_user" "$builder_public_ip"

  local remote_bootstrap_script
  remote_bootstrap_script="$(mktemp)"
  build_remote_bootstrap_script "$repo_url" "$repo_commit" "$base_chain_id" "$bridge_address" "$sync_timeout_seconds" >"$remote_bootstrap_script"
  chmod 0700 "$remote_bootstrap_script"

  local -a ssh_opts
  ssh_opts=(
    -i "$ssh_private_key"
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
    -o ServerAliveInterval=30
    -o ServerAliveCountMax=6
    -o TCPKeepAlive=yes
  )

  log "copying bootstrap script to builder instance"
  scp "${ssh_opts[@]}" "$remote_bootstrap_script" "$builder_user@$builder_public_ip:/home/$builder_user/bootstrap-operator-stack.sh"
  rm -f "$remote_bootstrap_script"

  log "running operator stack bootstrap and junocashd sync on builder"
  ssh "${ssh_opts[@]}" "$builder_user@$builder_public_ip" "bash /home/$builder_user/bootstrap-operator-stack.sh"

  mkdir -p "$(dirname "$metadata_out")" "$(dirname "$manifest_out")"
  scp "${ssh_opts[@]}" "$builder_user@$builder_public_ip:/home/$builder_user/operator-stack-bootstrap.json" "$metadata_out"

  local synced_block_height synced_block_hash junocash_release_tag juno_scan_release_tag
  synced_block_height="$(jq -r '.junocashd.synced_block_height // empty' "$metadata_out")"
  synced_block_hash="$(jq -r '.junocashd.synced_block_hash // empty' "$metadata_out")"
  junocash_release_tag="$(jq -r '.junocashd.release_tag // empty' "$metadata_out")"
  juno_scan_release_tag="$(jq -r '.juno_scan.release_tag // empty' "$metadata_out")"
  [[ "$synced_block_height" =~ ^[0-9]+$ ]] || die "invalid synced block height in metadata: $synced_block_height"
  [[ "$synced_block_hash" =~ ^(0x)?[0-9a-fA-F]{64}$ ]] || die "invalid synced block hash in metadata: $synced_block_hash"
  [[ -n "$junocash_release_tag" ]] || die "missing junocash release tag in metadata"
  [[ -n "$juno_scan_release_tag" ]] || die "missing juno-scan release tag in metadata"

  if [[ -z "$image_name" ]]; then
    image_name="${name_prefix}-h${synced_block_height}-$(date -u +%Y%m%dT%H%M%SZ)"
  fi
  if [[ -z "$image_description" ]]; then
    image_description="Operator stack AMI synced to junocashd block ${synced_block_height} (${synced_block_hash})"
  fi

  log "creating AMI from builder instance $cleanup_instance_id"
  local image_id
  image_id="$(
    aws_cli ec2 create-image \
      --instance-id "$cleanup_instance_id" \
      --name "$image_name" \
      --description "$image_description" \
      --no-reboot \
      --tag-specifications "ResourceType=image,Tags=[{Key=Name,Value=${image_name}},{Key=Project,Value=intents-juno},{Key=Stack,Value=operator-ami}]" \
      --query 'ImageId' \
      --output text
  )"
  [[ -n "$image_id" && "$image_id" != "None" ]] || die "failed to create AMI"

  log "waiting for AMI to become available: $image_id"
  aws_cli ec2 wait image-available --image-ids "$image_id"

  jq -n \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg image_name "$image_name" \
    --arg image_description "$image_description" \
    --arg aws_region "$aws_region" \
    --arg image_id "$image_id" \
    --arg repo_url "$repo_url" \
    --arg repo_commit "$repo_commit" \
    --arg source_ami_id "$source_ami_id" \
    --arg builder_instance_id "$cleanup_instance_id" \
    --arg junocash_release_tag "$junocash_release_tag" \
    --arg juno_scan_release_tag "$juno_scan_release_tag" \
    --argjson synced_block_height "$synced_block_height" \
    --arg synced_block_hash "$synced_block_hash" \
    --argjson base_chain_id "$base_chain_id" \
    --arg bridge_address "$bridge_address" \
    '{
      manifest_version: 1,
      generated_at: $generated_at,
      image: {
        name: $image_name,
        description: $image_description
      },
      regions: {
        ($aws_region): {
          ami_id: $image_id
        }
      },
      junocashd: {
        release_tag: $junocash_release_tag,
        synced_block_height: $synced_block_height,
        synced_block_hash: $synced_block_hash
      },
      juno_scan: {
        release_tag: $juno_scan_release_tag
      },
      stack: {
        base_chain_id: $base_chain_id,
        bridge_address: $bridge_address,
        services: [
          "junocashd.service",
          "juno-scan.service",
          "checkpoint-signer.service",
          "checkpoint-aggregator.service",
          "tss-host.service"
        ]
      },
      source: {
        repo_url: $repo_url,
        repo_commit: $repo_commit,
        source_ami_id: $source_ami_id,
        builder_instance_id: $builder_instance_id
      }
    }' >"$manifest_out"

  log "ami_id=$image_id"
  log "metadata=$metadata_out"
  log "manifest=$manifest_out"
  printf '%s\n' "$image_id"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    create) command_create "$@" ;;
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
