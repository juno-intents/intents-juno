# Proof Requestor Failover Runbook

## Scope

This runbook covers failover of the shared `proof-requestor` and `proof-funder` services between primary and DR regions while preserving:

- one requestor identity per chain
- one centralized funding source
- monotonic request-id allocation from Aurora

## Preconditions

1. DR region has warm deployments for:
   - `proof-requestor`
   - `proof-funder`
   - Kafka topics `proof.requests.v1`, `proof.fulfillments.v1`, `proof.failures.v1`
2. Aurora Global Database replication is healthy.
3. Shared requestor and funder keys are present in Secrets Manager in both regions.
4. DR deployment points to the same `requestor_address` and `chain_id`.

## Failover Steps

1. Freeze primary writers:
   - Scale primary `proof-requestor` ECS service to 0.
   - Scale primary `proof-funder` ECS task/Lambda concurrency to 0.
2. Promote Aurora writer in DR region.
3. Update DR service configs:
   - `postgres-dsn` to DR writer endpoint.
   - Kafka bootstrap servers to DR cluster.
   - `order_stream_url` if region-specific.
4. Start DR requestor/funder:
   - Scale DR `proof-requestor` to desired count.
   - Start DR `proof-funder` active loop.
5. Validate health:
   - `proof.fulfillments.v1` messages are emitted.
   - `proof.failures.v1` contains only expected retryables.
   - request-id sequence continues without resets (`proof_request_ids` table).
   - topups continue from the centralized funder key.

## Post-Failover Checks

1. Verify no duplicate submissions:
   - check `proof_jobs.request_id` unique continuity.
2. Verify lease ownership:
   - only one active `proof-funder` lease holder.
3. Verify balance guardrails:
   - requestor balance stays above `min_balance_wei`.

## Rollback

1. Scale DR requestor/funder to 0.
2. Restore Aurora writer in primary (or fail back global DB writer).
3. Repoint primary configs to healthy Kafka/Aurora endpoints.
4. Scale primary requestor/funder back up.

