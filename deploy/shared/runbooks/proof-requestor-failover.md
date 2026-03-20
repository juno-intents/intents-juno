# Proof Requestor Failover Runbook

## Scope

This runbook covers failover of the `production-shared` `proof-requestor` and `proof-funder` services between primary and DR regions while preserving:

- one requestor identity per chain
- one centralized funding source
- monotonic request-id allocation from Aurora

## Preconditions

1. DR region has warm deployments for:
   - `proof-requestor`
   - `proof-funder`
   - Kafka topics `proof.requests.v1`, `proof.fulfillments.v1`, `proof.failures.v1`
2. Aurora Global Database replication is healthy.
3. Distinct requestor and funder secrets are present in Secrets Manager in both regions and wired through `shared_sp1_requestor_secret_arn` and `shared_sp1_funder_secret_arn`.
4. DR deployment points to the same `requestor_address` and `chain_id`.
5. The DR `production-shared` stack already has a warm proof-role autoscaling group with a current launch-template version and healthy proof systemd units.
6. The shared IPFS NLB in the target region has at least two healthy targets, and the IPFS ASG is using ELB health checks rather than EC2-only liveness.

## Failover Steps

1. Freeze primary writers:
   - reduce the primary proof-role autoscaling group desired capacity to 0 after confirming no in-flight instance refresh is active
   - confirm no primary `proof-funder` instance still holds the lease
2. Promote Aurora writer in DR region.
3. Update DR stack inputs if the failover changes any regional endpoints:
   - `postgres-dsn` to DR writer endpoint.
   - Kafka bootstrap servers to the DR IAM-authenticated brokers.
   - `order_stream_url` if region-specific.
4. Start DR requestor/funder:
   - scale the DR proof-role autoscaling group to the target desired count
   - verify the DR `proof-funder` instance acquires the lease
5. Validate health:
   - `proof.fulfillments.v1` messages are emitted.
   - `proof.failures.v1` contains only expected retryables.
   - request-id sequence continues without resets (`proof_request_ids` table).
   - balance alerts continue from the centralized funder monitor.
   - the shared IPFS API remains reachable through the regional NLB during the cutover.

## Post-Failover Checks

1. Verify no duplicate submissions:
   - check `proof_jobs.request_id` unique continuity.
2. Verify lease ownership:
   - only one active `proof-funder` lease holder.
3. Verify balance guardrails:
   - requestor balance stays above `min_balance_wei`.
4. Verify the DR proof-role launch template still references only the requestor and funder secret ARNs required by that region.
5. Verify the DR proof-role instance profile still points only at the proof log groups and the configured proof-services repository.

## Rollback

1. Scale DR requestor/funder to 0.
2. Restore Aurora writer in primary (or fail back global DB writer).
3. Repoint primary configs to healthy Kafka/Aurora endpoints.
4. Scale the primary proof-role autoscaling group back up.
