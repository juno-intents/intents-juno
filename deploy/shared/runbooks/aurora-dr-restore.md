# Aurora DR Restore

Use this runbook to restore the shared Aurora cluster from the cross-region AWS Backup copy.

## Inputs

- Source environment name and deployment id
- Primary region and DR region
- DR backup vault name
- Target VPC, subnet group, and security groups for the restored cluster

## 1. Find the latest recovery point in DR

```bash
aws --region "$DR_REGION" backup list-recovery-points-by-backup-vault \
  --backup-vault-name "$DR_VAULT_NAME" \
  --by-resource-type Aurora \
  --query 'sort_by(RecoveryPoints,&CreationDate)[-1].RecoveryPointArn' \
  --output text
```

Record the `RecoveryPointArn`. Do not continue if it is empty.

## 2. Start the restore job

```bash
aws --region "$DR_REGION" backup start-restore-job \
  --iam-role-arn "$BACKUP_ROLE_ARN" \
  --recovery-point-arn "$RECOVERY_POINT_ARN" \
  --resource-type Aurora \
  --metadata "{
    \"dbClusterIdentifier\":\"$RESTORED_CLUSTER_ID\",
    \"engine\":\"aurora-postgresql\",
    \"dbSubnetGroupName\":\"$DB_SUBNET_GROUP\",
    \"vpcSecurityGroupIds\":\"$SECURITY_GROUP_IDS\",
    \"port\":\"5432\"
  }"
```

Wait for the restore job to complete successfully before proceeding.

## 3. Verify the restored cluster

```bash
aws --region "$DR_REGION" rds describe-db-clusters \
  --db-cluster-identifier "$RESTORED_CLUSTER_ID" \
  --query 'DBClusters[0].{Status:Status,Endpoint:Endpoint,ReaderEndpoint:ReaderEndpoint}'
```

The cluster must report `Status=available` and expose a writer endpoint.

## 4. Recreate instances and application routing

- Create at least two Aurora instances in distinct AZs for the restored cluster.
- Point the shared-service Terraform variables at the restored cluster only after verification.
- Re-run the shared-services canary before resuming operator or app rollouts.

## 5. Post-restore validation

- Confirm PostgreSQL connectivity with `pg_isready`.
- Confirm the checkpoint artifact bucket and Kafka cluster are still reachable from the restored environment.
- Capture the restore job id, recovery point ARN, and restored cluster endpoints in the incident timeline.
