locals {
  cloudtrail_bucket_base      = trim(replace(lower("${local.resource_name}-trail"), "_", "-"), "-")
  cloudtrail_bucket_name      = trim(substr(local.cloudtrail_bucket_base, 0, 63), "-")
  operations_metric_namespace = "IntentsJuno/Operations"
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = local.cloudtrail_bucket_name

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-trail"
  })
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail.arn}/AWSLogs/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json
}

resource "aws_cloudtrail" "production_shared" {
  name                          = "${local.resource_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "shared_postgres_instance_cpu" {
  for_each            = aws_rds_cluster_instance.shared
  alarm_name          = "${local.resource_name}-${each.value.availability_zone}-aurora-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 85
  alarm_description   = "Aurora instance CPU is elevated."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    DBInstanceIdentifier = each.value.identifier
  }
}

resource "aws_cloudwatch_metric_alarm" "shared_kafka_offline_partitions" {
  alarm_name          = "${local.resource_name}-msk-offline-partitions"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "OfflinePartitionsCount"
  namespace           = "AWS/Kafka"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "MSK has offline partitions."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    "Cluster Name" = aws_msk_cluster.shared.cluster_name
  }
}

resource "aws_cloudwatch_metric_alarm" "ipfs_unhealthy_hosts" {
  alarm_name          = "${local.resource_name}-ipfs-unhealthy"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/NetworkELB"
  period              = 300
  statistic           = "Average"
  threshold           = 0
  alarm_description   = "IPFS NLB has unhealthy targets."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    LoadBalancer = aws_lb.ipfs.arn_suffix
    TargetGroup  = aws_lb_target_group.ipfs_api.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "withdrawal_dlq_depth" {
  alarm_name          = "${local.resource_name}-withdrawal-dlq-depth"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "WithdrawalDLQDepth"
  namespace           = local.operations_metric_namespace
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Withdrawal DLQ depth is non-zero."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "confirmed_unmarked_count" {
  alarm_name          = "${local.resource_name}-confirmed-unmarked-count"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ConfirmedUnmarkedCount"
  namespace           = local.operations_metric_namespace
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Confirmed withdrawals remain unmarked on Base."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "mark_paid_circuit_open" {
  alarm_name          = "${local.resource_name}-mark-paid-circuit-open"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "MarkPaidCircuitOpen"
  namespace           = local.operations_metric_namespace
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Withdraw paid-marker circuit is open and automatic Base marking is disabled."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "deposit_proof_requested_count" {
  alarm_name          = "${local.resource_name}-deposit-proof-requested-count"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 10
  metric_name         = "DepositProofRequestedCount"
  namespace           = local.operations_metric_namespace
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Deposits have remained proof-requested for at least 10 minutes."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "deposit_submitted_count" {
  alarm_name          = "${local.resource_name}-deposit-submitted-count"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 10
  metric_name         = "DepositSubmittedCount"
  namespace           = local.operations_metric_namespace
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Deposits have remained submitted for at least 10 minutes."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "min_withdrawal_time_to_expiry_seconds" {
  alarm_name          = "${local.resource_name}-min-withdrawal-time-to-expiry"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "MinWithdrawalTimeToExpirySeconds"
  namespace           = local.operations_metric_namespace
  period              = 60
  statistic           = "Minimum"
  threshold           = 1800
  alarm_description   = "The minimum withdrawal time-to-expiry runway is below 30 minutes."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "checkpoint_pin_backlog" {
  alarm_name          = "${local.resource_name}-checkpoint-pin-backlog"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CheckpointPinBacklog"
  namespace           = local.operations_metric_namespace
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Checkpoint packages are accumulating faster than IPFS pinning drains them."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}

resource "aws_cloudwatch_metric_alarm" "tss_session_saturation" {
  alarm_name          = "${local.resource_name}-tss-session-saturation"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "TSSSessionSaturation"
  namespace           = local.operations_metric_namespace
  period              = 60
  statistic           = "Maximum"
  threshold           = 0.8
  alarm_description   = "TSS session saturation is above 80%."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions
}
