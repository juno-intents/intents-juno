# DKG + Base Testnet E2E

This folder provides live-network e2e automation for:

1. 5-operator DKG ceremony
2. per-operator `dkg-backup.zip` creation
3. restore with only `dkg-backup.zip`
4. operator boot verification after restore
5. Base testnet contract deploy + bridge smoke flow (Juno->Base mint and Base->Juno finalize path)

Current limitation:
- The workflow currently executes bridge transactions on Base testnet.
- It does not yet broadcast Juno-chain deposit/withdraw payout transactions end-to-end from this repo.
- The Base `finalize_withdraw` tx hash is no longer accepted as a Juno proof surrogate.
- `run-testnet-e2e.sh` now auto-resolves the canonical Juno execution tx hash from `--boundless-withdraw-witness-txid` when available.
- When Juno RPC credentials are provided, `run-testnet-e2e.sh` also performs a `sendrawtransaction` rebroadcast probe for that txid.
- Use `--bridge-juno-execution-tx-hash` only to override the auto-resolved value.
- `JUNO_FUNDER_PRIVATE_KEY_HEX` is still required in CI and is reserved for the upcoming Juno-chain execution stage.

## Scripts

- `create-funder-wallets.sh`:
  - Creates and saves local Base/Juno funder key files under `tmp/`.
  - Creates a Juno testnet Orchard wallet/account/address and seed phrase file for funding.
- `run-dkg-backup-restore.sh`:
  - Runs DKG, exports backup packages, deletes runtime state, restores from backup zips, verifies operator boot.
- `run-testnet-e2e.sh`:
  - Orchestrates DKG backup/restore plus Base testnet deploy and bridge smoke transactions.
  - Supports `--dkg-summary-path` to reuse a precomputed distributed DKG result.
  - Requires shared Postgres/Kafka/IPFS (`--shared-postgres-dsn`, `--shared-kafka-brokers`, `--shared-ipfs-api-url`), validates them via `cmd/shared-infra-e2e`, then runs centralized `proof-requestor` + `proof-funder` services (ECS-managed when shared ECS options are provided) and submits proof jobs through Kafka topics.
- `run-testnet-e2e-aws.sh`:
  - Provisions a dedicated AWS EC2 runner with Terraform, managed shared services (Aurora Postgres + MSK + ECS + IPFS pinning ASG), and one dedicated EC2 per operator.
  - Supports pre-baked AMIs (`--runner-ami-id`, `--operator-ami-id`, `--shared-ami-id`) so operators can boot from pre-synced images (`--shared-ami-id` applies to IPFS ASG instances).
  - Executes distributed DKG + backup/restore across those operator hosts, then runs `run-testnet-e2e.sh` against the generated `dkg-summary.json`.
  - Exports each restored operator key package to an e2e-scoped KMS+S3 backend and records receipts in the distributed DKG summary.
  - Collects artifacts and destroys infra by default.
## AWS Live E2E

- Terraform stack:
  - `deploy/shared/terraform/live-e2e`
- Wrapper:
  - `deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh`
- GitHub workflow:
  - `.github/workflows/e2e-testnet-deploy-aws.yml`
- Operator AMI release workflow:
  - `.github/workflows/release-operator-stack-ami.yml`

The AWS workflow is designed for high-fidelity live runs and includes teardown on both success and failure paths:

1. `run-testnet-e2e-aws.sh run ...` provisions EC2 and executes e2e remotely.
2. `run-testnet-e2e-aws.sh` trap performs destroy on exit.
3. Workflow fallback step always invokes `run-testnet-e2e-aws.sh cleanup ...` as a second destroy guard.
4. When `operator_ami_id` input is empty, `.github/workflows/e2e-testnet-deploy-aws.yml` resolves `operator-stack-ami-latest` release metadata and injects `--operator-ami-id` automatically.

To bake and release the full operator AMI (synced `junocashd` + `juno-scan` + checkpoint services + `tss-host`), run:

- `.github/workflows/release-operator-stack-ami.yml`

The workflow uses:

- `deploy/shared/runbooks/build-operator-stack-ami.sh`

GitHub secrets expected by `.github/workflows/e2e-testnet-deploy-aws.yml`:

- AWS auth:
  - Either `AWS_ROLE_TO_ASSUME` (OIDC) or static creds (`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`).
- Funding keys:
  - `BASE_FUNDER_PRIVATE_KEY_HEX`
  - `JUNO_FUNDER_PRIVATE_KEY_HEX`
  - `BOUNDLESS_REQUESTOR_PRIVATE_KEY_HEX`

Local invocation example:

```bash
./deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh run \
  --aws-region us-east-1 \
  --base-funder-key-file ./tmp/funders/base-funder.key \
  --juno-funder-key-file ./tmp/funders/juno-funder.key \
  --boundless-requestor-key-file ./tmp/funders/boundless-requestor-mainnet.key \
  -- \
  --base-rpc-url https://base-sepolia.drpc.org \
  --base-chain-id 84532 \
  --bridge-verifier-address 0xVerifierRouterAddress \
  --bridge-deposit-image-id 0x... \
  --bridge-withdraw-image-id 0x... \
  --boundless-deposit-program-url https://.../deposit-guest.elf \
  --boundless-withdraw-program-url https://.../withdraw-guest.elf
```

## Boundless Mode

- The e2e runs in strict proof mode only.
- `run-testnet-e2e.sh` always uses `--boundless-auto`.
- `--boundless-input-mode` is locked to `guest-witness-v1`.
- Guest witness mode requires:
  - explicit witness inputs only (auto generation is disabled in this flow):
    - `--boundless-deposit-owallet-ivk-hex`
    - `--boundless-withdraw-owallet-ovk-hex`
    - `--boundless-deposit-witness-item-file` (repeatable)
    - `--boundless-withdraw-witness-item-file` (repeatable)
    - `--bridge-deposit-final-orchard-root` (required in manual witness mode)
    - `--bridge-withdraw-final-orchard-root` (optional; defaults to deposit root)
    - `--bridge-deposit-checkpoint-height` (required in manual witness mode)
    - `--bridge-deposit-checkpoint-block-hash` (required in manual witness mode)
    - `--bridge-withdraw-checkpoint-height` (optional; defaults to deposit checkpoint height)
    - `--bridge-withdraw-checkpoint-block-hash` (optional; defaults to deposit checkpoint block hash)
  - optional witness extraction from live `juno-scan` + `junocashd` when witness item files are omitted:
    - `--boundless-witness-juno-scan-url`
    - `--boundless-witness-juno-rpc-url`
    - `--boundless-deposit-witness-wallet-id`
    - `--boundless-deposit-witness-txid`
    - `--boundless-deposit-witness-action-index`
    - `--boundless-withdraw-witness-wallet-id`
    - `--boundless-withdraw-witness-txid`
    - `--boundless-withdraw-witness-action-index`
    - `--boundless-withdraw-witness-withdrawal-id-hex`
    - `--boundless-withdraw-witness-recipient-raw-address-hex`
    - when extraction is used, checkpoint height/hash flags are auto-filled from witness metadata (`anchor_height` + `anchor_block_hash`)
  - extraction command is also available directly:
    - `go run ./cmd/juno-witness-extract deposit ...`
    - `go run ./cmd/juno-witness-extract withdraw ...`
- No manual seal injection, no prepare-only path, and no no-op verifier path are supported in this flow.

Pricing policy and calculator:

- See `deploy/shared/runbooks/boundless-auction-pricing.md`.
- Run `deploy/shared/runbooks/calc-boundless-auction.sh --cycle-count <cycles>` to compute a baseline profile.

## Quick Start

```bash
./deploy/operators/dkg/e2e/create-funder-wallets.sh create --force

./deploy/operators/dkg/e2e/run-testnet-e2e.sh run \
  --base-rpc-url https://base-sepolia-rpc.example \
  --base-funder-key-file ./tmp/funders/base-funder.key \
  --shared-postgres-dsn postgresql://postgres:password@127.0.0.1:5432/intents_e2e?sslmode=disable \
  --shared-kafka-brokers 127.0.0.1:9092 \
  --shared-ipfs-api-url http://127.0.0.1:5001 \
  --bridge-verifier-address 0xVerifierRouterAddress \
  --bridge-deposit-image-id 0x... \
  --bridge-withdraw-image-id 0x... \
  --boundless-requestor-key-file ./tmp/funders/boundless-requestor-mainnet.key \
  --boundless-deposit-program-url https://.../deposit-guest.elf \
  --boundless-withdraw-program-url https://.../withdraw-guest.elf \
  --force
```
