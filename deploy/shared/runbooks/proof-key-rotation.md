# Proof Key Rotation Runbook

## Scope

Rotate centralized keys used by the `production-shared` stack:

- `proof-requestor` key (`shared_sp1_requestor_secret_arn`)
- `proof-funder` key (`shared_sp1_funder_secret_arn`)

No per-operator keys are used for SP1 proof funding.

## Preconditions

1. New keys are generated and funded as required.
2. New secrets are stored in AWS Secrets Manager.
3. The new Terraform inputs reference distinct secret ARNs. Reusing one ARN for both services is not allowed.
4. Access policy for the proof-requestor and proof-funder execution roles allows reading only the corresponding new secret ARN, writing only to the corresponding CloudWatch log group, and pulling only from the configured proof-services ECR repository. The only wildcard left in the execution role policy should be `ecr:GetAuthorizationToken`.
5. `proof-requestor` and `proof-funder` deployments are healthy in the `production-shared` ECS cluster.

## Rotation Procedure

1. Create new secret versions:
   - requestor private key secret
   - funder private key secret
2. Update the `production-shared` Terraform inputs:
   - `shared_sp1_requestor_secret_arn` -> new requestor ARN/version
   - `shared_sp1_funder_secret_arn` -> new funder ARN/version
3. Apply the shared stack and confirm the new task definitions reference the new secret ARNs.
4. Roll `proof-requestor` first:
   - keep `deployment_minimum_healthy_percent = 100`
   - keep `deployment_maximum_percent = 200`
   - wait for the new task to pass health checks before the old task drains
   - verify successful SP1 network submissions
5. Roll `proof-funder` second:
   - keep `deployment_minimum_healthy_percent = 100`
   - keep `deployment_maximum_percent = 200`
   - verify low-balance alerting remains healthy
6. Keep old key enabled until:
   - no tasks reference old secret
   - no pending transactions require old signer
7. Revoke/decommission old key and secret value.

## Validation Checklist

1. Requestor still emits fulfillments/failures.
2. `proof_jobs` records continue updating (no stalled submissions).
3. Requestor balance polling and critical alerts continue.
4. No increase in auth/signing errors from SP1 operations.
5. The proof-requestor execution role cannot read the funder secret ARN, and the proof-funder execution role cannot read the requestor secret ARN.
6. The execution roles remain scoped to the proof-services repository and their own CloudWatch log groups after the rollout.

## Emergency Rollback

1. Revert the Terraform inputs to the previous known-good secret ARNs.
2. Re-apply the `production-shared` stack.
3. Confirm both ECS services rolled back cleanly and submission/balance-alert health recovered.
