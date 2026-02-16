# Boundless Auction Pricing Baseline

This runbook defines the default proof-auction baseline for shared `proof-requestor` + `proof-funder`.

## Goals

- Keep request costs bounded.
- Keep requestor funding predictable.
- Use one repeatable pricing method for staging and production.

## Runtime Defaults (as configured)

- `onchain-min-balance-wei`: `50000000000000000` (0.05 ETH)
- `onchain-target-balance-wei`: `200000000000000000` (0.20 ETH)
- `onchain-max-price-per-proof-wei`: `250000000000000` (0.00025 ETH)
- `onchain-max-stake-per-proof-wei`: `20000000000000000000` (20 token units, 18 decimals)

Funder guardrails:

- `min-balance-wei`: `50000000000000000`
- `target-balance-wei`: `200000000000000000`
- `critical-balance-wei`: `10000000000000000`
- `max-topup-per-tx-wei`: `200000000000000000`

## Method

Given:

- `cycles`
- `executor_hz` (default `30_000_000`)
- `prover_hz` (default `1_000_000`)
- `block_time_seconds` (default `2`)
- `min_price_wei_per_gcycle` (default `100000000000000`)
- `max_price_wei_per_gcycle` (default `250000000000000`)

Compute:

- `execution_seconds = ceil(cycles / executor_hz)`
- `proving_seconds = ceil(cycles / prover_hz)`
- `ramp_up_start_seconds = 5 * execution_seconds`
- `ramp_up_period_seconds = 10 * execution_seconds`
- `ramp_up_period_blocks = ceil(ramp_up_period_seconds / block_time_seconds)`
- `lock_timeout_seconds = ceil(1.25 * proving_seconds)`
- `timeout_seconds = 3 * proving_seconds`
- `min_price_wei = ceil(cycles * min_price_wei_per_gcycle / 1e9)`
- `max_price_wei = ceil(cycles * max_price_wei_per_gcycle / 1e9)`

Collateral baseline:

- Base mainnet (8453): `20e18`
- Base Sepolia (84532): `5e18`
- Ethereum Sepolia (11155111): `5e18`

## Calculator

Use the built-in calculator command:

```bash
go run ./cmd/boundless-auction-calc \
  --chain-id 8453 \
  --cycle-count 500000000
```

This outputs a JSON profile with the computed timing, price, and recommended collateral floor.
