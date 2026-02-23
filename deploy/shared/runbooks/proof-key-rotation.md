# Proof Key Rotation Runbook

## Scope

Rotate centralized keys used by shared proof infrastructure:

- `proof-requestor` key (`requestor_key_secret_arn`)
- `proof-funder` key (`owner_key_secret_arn`)

No per-operator keys are used for SP1 proof funding.

## Preconditions

1. New keys are generated and funded as required.
2. New secrets are stored in AWS Secrets Manager.
3. Access policy for ECS task roles allows reading new secret ARNs.
4. `proof-requestor` and `proof-funder` deployments are healthy.

## Rotation Procedure

1. Create new secret versions:
   - requestor private key secret
   - funder owner private key secret
2. Update runtime config:
   - `requestor_key_secret_arn` -> new ARN/version
   - `owner_key_secret_arn` -> new ARN/version
3. Roll `proof-requestor` service:
   - deploy with new secret reference
   - verify successful SP1 network submissions
4. Roll `proof-funder` service:
   - deploy with new secret reference
   - verify low-balance alerting remains healthy
5. Keep old key enabled until:
   - no tasks reference old secret
   - no pending transactions require old signer
6. Revoke/decommission old key and secret value.

## Validation Checklist

1. Requestor still emits fulfillments/failures.
2. `proof_jobs` records continue updating (no stalled submissions).
3. Requestor balance polling and critical alerts continue.
4. No increase in auth/signing errors from SP1 operations.

## Emergency Rollback

1. Revert secret ARNs to previous known-good values.
2. Redeploy `proof-requestor` and `proof-funder`.
3. Confirm submission and balance-alert health recovered.
