# SP1 Auction Pricing Baseline

This runbook defines the default SP1 network auction baseline for shared `proof-requestor` + `proof-funder`.

## Goals

- Keep request costs bounded.
- Keep requestor credit balance predictable.
- Use one repeatable pricing method for staging and production.

## Runtime Defaults (as configured)

- `sp1-max-price-per-pgu`: `2000000000`
- `sp1-deposit-pgu-estimate`: `1000000`
- `sp1-withdraw-pgu-estimate`: `1000000`
- `sp1-groth16-base-fee-wei`: `200000000000000000` (0.2 PROVE)
- `sp1-min-auction-period`: `85`
- `sp1-auction-timeout`: `625s`
- `sp1-request-timeout`: `1500s`

Credit guardrails:

- `projected_pair_cost_wei = (2 * sp1_groth16_base_fee_wei) + ((sp1_deposit_pgu_estimate + sp1_withdraw_pgu_estimate) * sp1_max_price_per_pgu)`
- `projected_with_overhead_wei = ceil(projected_pair_cost_wei * 1.2)`
- `required_credit_buffer_wei = projected_with_overhead_wei * 3`
- `proof-funder min-balance-wei = required_credit_buffer_wei`
- `proof-funder critical-balance-wei = projected_with_overhead_wei`

## Method

Given:

- `cycles`
- `executor_hz` (default `30_000_000`)
- `prover_hz` (default `1_000_000`)
- `block_time_seconds` (default `2`)
- `max_price_wei_per_gcycle` (default `250000000000000`)

Compute:

- `execution_seconds = ceil(cycles / executor_hz)`
- `proving_seconds = ceil(cycles / prover_hz)`
- `min_auction_period_seconds = 10 * execution_seconds`
- `auction_timeout_seconds = ceil(1.25 * proving_seconds)`
- `request_timeout_seconds = 3 * proving_seconds`
- `max_price_per_pgu = ceil(cycles * max_price_wei_per_gcycle / 1e9)`

## Calculator

Use the built-in calculator command:

```bash
go run ./cmd/sp1-auction-calc \
  --chain-id 8453 \
  --cycle-count 500000000
```

This outputs a JSON profile with the computed timing and price baseline. Use it to set:

- `sp1-max-price-per-pgu` from `max_price_wei`
- `sp1-min-auction-period` from `ramp_up_start_seconds`
- `sp1-auction-timeout` from `lock_timeout_seconds`
- `sp1-request-timeout` from `timeout_seconds`
