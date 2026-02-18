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
  - Optionally validates shared Postgres/Kafka infra first via `cmd/shared-infra-e2e` when `--shared-postgres-dsn` and `--shared-kafka-brokers` are provided.
- `run-testnet-e2e-aws.sh`:
  - Provisions a dedicated AWS EC2 runner with Terraform, plus shared-services EC2 (Postgres+Kafka by default) and one dedicated EC2 per operator.
  - Executes distributed DKG + backup/restore across those operator hosts, then runs `run-testnet-e2e.sh` against the generated `dkg-summary.json`.
  - Collects artifacts and destroys infra by default.
## AWS Live E2E

- Terraform stack:
  - `deploy/shared/terraform/live-e2e`
- Wrapper:
  - `deploy/operators/dkg/e2e/run-testnet-e2e-aws.sh`
- GitHub workflow:
  - `.github/workflows/e2e-testnet-deploy-aws.yml`

The AWS workflow is designed for high-fidelity live runs on a powerful machine and includes teardown on both success and failure paths:

1. `run-testnet-e2e-aws.sh run ...` provisions EC2 and executes e2e remotely.
2. `run-testnet-e2e-aws.sh` trap performs destroy on exit.
3. Workflow fallback step always invokes `run-testnet-e2e-aws.sh cleanup ...` as a second destroy guard.

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
  --base-rpc-url https://sepolia.base.org \
  --base-chain-id 84532 \
  --bridge-verifier-address 0xVerifierRouterAddress \
  --bridge-deposit-image-id 0x... \
  --bridge-withdraw-image-id 0x... \
  --boundless-deposit-program-url https://.../deposit-guest.elf \
  --boundless-withdraw-program-url https://.../withdraw-guest.elf
```

## Boundless Mode

- The e2e runs in strict proof mode only.
- `run-testnet-e2e.sh` always uses `--boundless-auto` and `--boundless-input-mode private-input`.
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
  --bridge-verifier-address 0xVerifierRouterAddress \
  --bridge-deposit-image-id 0x... \
  --bridge-withdraw-image-id 0x... \
  --boundless-requestor-key-file ./tmp/funders/boundless-requestor-mainnet.key \
  --boundless-deposit-program-url https://.../deposit-guest.elf \
  --boundless-withdraw-program-url https://.../withdraw-guest.elf \
  --force
```
