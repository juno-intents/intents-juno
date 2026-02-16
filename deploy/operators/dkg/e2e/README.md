# DKG + Base Testnet E2E

This folder provides live-network e2e automation for:

1. 5-operator DKG ceremony
2. per-operator `dkg-backup.zip` creation
3. restore with only `dkg-backup.zip`
4. operator boot verification after restore
5. Base testnet contract deploy + bridge smoke flow

## Scripts

- `create-funder-wallets.sh`:
  - Creates and saves local Base/Juno funder key files under `tmp/`.
- `run-dkg-backup-restore.sh`:
  - Runs DKG, exports backup packages, deletes runtime state, restores from backup zips, verifies operator boot.
- `run-testnet-e2e.sh`:
  - Orchestrates DKG backup/restore plus Base testnet deploy and bridge smoke transactions.

## Boundless Note

For this testnet e2e, the bridge deploy path uses a no-op verifier contract so we can validate operator quorum signatures and bridge transaction flow without depending on Boundless testnet availability.

## Quick Start

```bash
./deploy/operators/dkg/e2e/create-funder-wallets.sh create --force

./deploy/operators/dkg/e2e/run-testnet-e2e.sh run \
  --base-rpc-url https://base-sepolia-rpc.example \
  --base-funder-key-file ./tmp/funders/base-funder.key \
  --force
```
