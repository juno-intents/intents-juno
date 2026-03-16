locals {
  cloudtrail_bucket_base = trim(replace(lower("${local.resource_name}-trail"), "_", "-"), "-")
  cloudtrail_bucket_name = trim(substr(local.cloudtrail_bucket_base, 0, 63), "-")
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket        = local.cloudtrail_bucket_name
  force_destroy = true

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

resource "aws_cloudtrail" "live_e2e" {
  name                          = "${local.resource_name}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "runner_status" {
  alarm_name          = "${local.resource_name}-runner-status"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Runner instance failed EC2 status checks."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    InstanceId = aws_instance.runner.id
  }
}

resource "aws_cloudwatch_metric_alarm" "operator_status" {
  count               = var.operator_instance_count
  alarm_name          = "${local.resource_name}-operator-${count.index + 1}-status"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Operator instance failed EC2 status checks."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    InstanceId = aws_instance.operator[count.index].id
  }
}

resource "aws_cloudwatch_metric_alarm" "shared_postgres_instance_cpu" {
  for_each            = var.provision_shared_services ? aws_rds_cluster_instance.shared : {}
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
  count               = var.provision_shared_services ? 1 : 0
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
    "Cluster Name" = aws_msk_cluster.shared[0].cluster_name
  }
}

resource "aws_cloudwatch_metric_alarm" "proof_requestor_running" {
  count               = var.provision_shared_services && var.shared_ecs_desired_count > 0 ? 1 : 0
  alarm_name          = "${local.resource_name}-proof-requestor-running"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "RunningTaskCount"
  namespace           = "ECS/ContainerInsights"
  period              = 300
  statistic           = "Average"
  threshold           = var.shared_ecs_desired_count
  alarm_description   = "proof-requestor ECS service has fewer running tasks than expected."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    ClusterName = aws_ecs_cluster.shared[0].name
    ServiceName = aws_ecs_service.proof_requestor[0].name
  }
}

resource "aws_cloudwatch_metric_alarm" "proof_funder_running" {
  count               = var.provision_shared_services && var.shared_ecs_desired_count > 0 ? 1 : 0
  alarm_name          = "${local.resource_name}-proof-funder-running"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "RunningTaskCount"
  namespace           = "ECS/ContainerInsights"
  period              = 300
  statistic           = "Average"
  threshold           = var.shared_ecs_desired_count
  alarm_description   = "proof-funder ECS service has fewer running tasks than expected."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    ClusterName = aws_ecs_cluster.shared[0].name
    ServiceName = aws_ecs_service.proof_funder[0].name
  }
}

resource "aws_cloudwatch_metric_alarm" "ipfs_unhealthy_hosts" {
  count               = var.provision_shared_services ? 1 : 0
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
    LoadBalancer = aws_lb.ipfs[0].arn_suffix
    TargetGroup  = aws_lb_target_group.ipfs_api[0].arn_suffix
  }
}
