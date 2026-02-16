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
- `run-testnet-e2e-aws.sh`:
  - Provisions a dedicated AWS EC2 runner with Terraform, executes `run-testnet-e2e.sh` on that host, collects artifacts, and destroys infra by default.

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
  - `BOUNDLESS_REQUESTOR_PRIVATE_KEY_HEX` (required when `boundless_auto=true`)

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
  --boundless-auto \
  --boundless-deposit-program-url https://.../deposit-guest.elf \
  --boundless-withdraw-program-url https://.../withdraw-guest.elf
```

## Boundless Modes

- Default mode (no verifier args): deploys a no-op verifier and runs full bridge smoke transactions for infra validation.
- Real verifier mode: pass `--bridge-verifier-address` and both seal files (`--bridge-deposit-seal-file`, `--bridge-withdraw-seal-file`) to verify real seals against a live verifier router.
- Auto Boundless mode: pass `--boundless-auto` plus Boundless requestor key/program URLs to submit proofs, wait for fulfillment, and execute callback transactions automatically.
- Prepare-only mode: pass `--bridge-prepare-only` to generate proof input artifacts and skip `mintBatch/finalizeWithdrawBatch`. This supports manual callback flows when proof submission/fulfillment is handled outside the testnet stack.

Pricing policy and calculator:

- See `deploy/shared/runbooks/boundless-auction-pricing.md`.
- Run `deploy/shared/runbooks/calc-boundless-auction.sh --cycle-count <cycles>` to compute a baseline profile.

## Quick Start

```bash
./deploy/operators/dkg/e2e/create-funder-wallets.sh create --force

./deploy/operators/dkg/e2e/run-testnet-e2e.sh run \
  --base-rpc-url https://base-sepolia-rpc.example \
  --base-funder-key-file ./tmp/funders/base-funder.key \
  --force

# Phase 2 automatic proof flow (Boundless submit + wait + callback).
./deploy/operators/dkg/e2e/run-testnet-e2e.sh run \
  --base-rpc-url https://base-sepolia-rpc.example \
  --base-funder-key-file ./tmp/funders/base-funder.key \
  --bridge-verifier-address 0xVerifierRouterAddress \
  --bridge-deposit-image-id 0x... \
  --bridge-withdraw-image-id 0x... \
  --boundless-auto \
  --boundless-requestor-key-file ./tmp/funders/boundless-requestor-mainnet.key \
  --boundless-deposit-program-url https://.../deposit-guest.elf \
  --boundless-withdraw-program-url https://.../withdraw-guest.elf \
  --force

# Phase 2 prepare-only artifact generation for manual callback/proof submission.
./deploy/operators/dkg/e2e/run-testnet-e2e.sh run \
  --base-rpc-url https://base-sepolia-rpc.example \
  --base-funder-key-file ./tmp/funders/base-funder.key \
  --bridge-verifier-address 0xVerifierRouterAddress \
  --bridge-deposit-image-id 0x... \
  --bridge-withdraw-image-id 0x... \
  --bridge-prepare-only \
  --force

# Phase 2 execution with real seals.
./deploy/operators/dkg/e2e/run-testnet-e2e.sh run \
  --base-rpc-url https://base-sepolia-rpc.example \
  --base-funder-key-file ./tmp/funders/base-funder.key \
  --bridge-verifier-address 0xVerifierRouterAddress \
  --bridge-deposit-image-id 0x... \
  --bridge-withdraw-image-id 0x... \
  --bridge-deposit-seal-file ./tmp/seals/deposit.seal.hex \
  --bridge-withdraw-seal-file ./tmp/seals/withdraw.seal.hex \
  --force
```
