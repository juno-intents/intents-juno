provider "aws" {
  region = var.aws_region
}

locals {
  resource_name = "${var.name_prefix}-${var.deployment_id}"
  resource_slug = trim(replace(lower(local.resource_name), "_", "-"), "-")

  common_tags = {
    Project    = "intents-juno"
    ManagedBy  = "terraform"
    Stack      = "production-shared"
    Deployment = var.deployment_id
  }
}

data "aws_vpc" "selected" {
  id = var.vpc_id
}

data "aws_subnet" "shared" {
  for_each = toset(var.shared_subnet_ids)
  id       = each.value
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  shared_subnets            = sort(var.shared_subnet_ids)
  shared_subnet_cidrs       = [for subnet in data.aws_subnet.shared : subnet.cidr_block]
  shared_ipfs_ingress_cidrs = distinct(concat(local.shared_subnet_cidrs, var.shared_ipfs_client_cidr_blocks))
  ipfs_ami_id               = var.shared_ipfs_ami_id != "" ? var.shared_ipfs_ami_id : data.aws_ami.ubuntu.id

  aurora_final_snapshot_identifier             = trimspace(var.shared_postgres_final_snapshot_identifier) != "" ? trimspace(var.shared_postgres_final_snapshot_identifier) : "${local.resource_slug}-shared-aurora-final"
  shared_proof_service_image_override          = trimspace(var.shared_proof_service_image)
  shared_proof_service_image                   = local.shared_proof_service_image_override != "" ? local.shared_proof_service_image_override : "${aws_ecr_repository.proof_services.repository_url}:latest"
  shared_proof_service_image_uses_ecr          = local.shared_proof_service_image_override == "" || can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[^.]+\\.amazonaws\\.com/.+", local.shared_proof_service_image_override))
  shared_proof_service_image_requires_ecr_pull = local.shared_proof_service_image_uses_ecr
  shared_proof_service_ecr_repository_arn      = local.shared_proof_service_image_override == "" ? aws_ecr_repository.proof_services.arn : trimspace(var.shared_proof_service_image_ecr_repository_arn)
  shared_sp1_requestor_address                 = trimspace(var.shared_sp1_requestor_address)
  shared_proof_runtime_enabled                 = var.shared_ecs_desired_count > 0
  shared_proof_guest_release_tag               = trimspace(var.shared_bridge_guest_release_tag)
  shared_deposit_image_id                      = lower(trimspace(var.shared_deposit_image_id))
  shared_withdraw_image_id                     = lower(trimspace(var.shared_withdraw_image_id))
  shared_deposit_image_id_hex                  = replace(local.shared_deposit_image_id, "0x", "")
  shared_withdraw_image_id_hex                 = replace(local.shared_withdraw_image_id, "0x", "")
  shared_postgres_dsn                          = format("postgres://%s:%s@%s:%d/%s?sslmode=require", urlencode(var.shared_postgres_user), urlencode(var.shared_postgres_password), aws_rds_cluster.shared.endpoint, var.shared_postgres_port, urlencode(var.shared_postgres_db))
  shared_kafka_bootstrap_brokers               = aws_msk_cluster.shared.bootstrap_brokers_sasl_iam
  shared_kafka_topic_arn_prefix                = replace(aws_msk_cluster.shared.arn, ":cluster/", ":topic/")
  shared_kafka_group_arn_prefix                = replace(aws_msk_cluster.shared.arn, ":cluster/", ":group/")
  shared_proof_request_topic                   = "proof.requests.v1"
  shared_proof_result_topic                    = "proof.fulfillments.v1"
  shared_proof_failure_topic                   = "proof.failures.v1"
  shared_ops_alert_topic                       = "ops.alerts.v1"
  shared_proof_requestor_group                 = "proof-requestor"
  shared_sp1_projected_pair_cost_wei           = (var.shared_sp1_groth16_base_fee_wei * 2) + (var.shared_sp1_max_price_per_pgu * (var.shared_sp1_deposit_pgu_estimate + var.shared_sp1_withdraw_pgu_estimate))
  shared_sp1_projected_with_overhead           = floor(((local.shared_sp1_projected_pair_cost_wei * 120) + 99) / 100)
  shared_sp1_required_credit_buffer            = local.shared_sp1_projected_with_overhead * 3
  shared_sp1_deposit_program_url               = can(regex("^0x[0-9a-f]{64}$", local.shared_deposit_image_id)) ? format("https://github.com/juno-intents/intents-juno/releases/download/%s/deposit-guest-%s.elf", local.shared_proof_guest_release_tag, local.shared_deposit_image_id_hex) : ""
  shared_sp1_withdraw_program_url              = can(regex("^0x[0-9a-f]{64}$", local.shared_withdraw_image_id)) ? format("https://github.com/juno-intents/intents-juno/releases/download/%s/withdraw-guest-%s.elf", local.shared_proof_guest_release_tag, local.shared_withdraw_image_id_hex) : ""
  shared_proof_requestor_command = [
    "/usr/local/bin/proof-requestor",
    "--postgres-dsn", local.shared_postgres_dsn,
    "--store-driver", "postgres",
    "--owner", "${local.resource_name}-proof-requestor",
    "--sp1-requestor-address", local.shared_sp1_requestor_address,
    "--sp1-requestor-key-secret-arn", "PROOF_REQUESTOR_KEY",
    "--sp1-requestor-key-env", "PROOF_REQUESTOR_KEY",
    "--secrets-driver", "env",
    "--chain-id", tostring(var.shared_base_chain_id),
    "--input-topic", local.shared_proof_request_topic,
    "--result-topic", local.shared_proof_result_topic,
    "--failure-topic", local.shared_proof_failure_topic,
    "--max-inflight-requests", "32",
    "--request-timeout", format("%ds", var.shared_sp1_request_timeout_seconds),
    "--queue-driver", "kafka",
    "--queue-brokers", local.shared_kafka_bootstrap_brokers,
    "--queue-group", local.shared_proof_requestor_group,
    "--sp1-bin", "/usr/local/bin/sp1-prover-adapter",
  ]
  shared_proof_funder_command = [
    "/usr/local/bin/proof-funder",
    "--postgres-dsn", local.shared_postgres_dsn,
    "--lease-driver", "postgres",
    "--owner-id", "${local.resource_name}-proof-funder",
    "--sp1-requestor-address", local.shared_sp1_requestor_address,
    "--min-balance-wei", tostring(local.shared_sp1_required_credit_buffer),
    "--critical-balance-wei", tostring(local.shared_sp1_projected_with_overhead),
    "--queue-driver", "kafka",
    "--queue-brokers", local.shared_kafka_bootstrap_brokers,
    "--sp1-bin", "/usr/local/bin/sp1-prover-adapter",
  ]
  shared_proof_requestor_environment = [
    {
      name  = "JUNO_QUEUE_KAFKA_TLS"
      value = "true"
    },
    {
      name  = "JUNO_QUEUE_KAFKA_AUTH_MODE"
      value = "aws-msk-iam"
    },
    {
      name  = "JUNO_QUEUE_KAFKA_AWS_REGION"
      value = var.aws_region
    },
    {
      name  = "SP1_NETWORK_RPC_URL"
      value = trimspace(var.shared_sp1_rpc_url)
    },
    {
      name  = "SP1_MAX_PRICE_PER_PGU"
      value = tostring(var.shared_sp1_max_price_per_pgu)
    },
    {
      name  = "SP1_MIN_AUCTION_PERIOD"
      value = tostring(var.shared_sp1_min_auction_period)
    },
    {
      name  = "SP1_AUCTION_TIMEOUT_SECONDS"
      value = tostring(var.shared_sp1_auction_timeout_seconds)
    },
    {
      name  = "SP1_REQUEST_TIMEOUT_SECONDS"
      value = tostring(var.shared_sp1_request_timeout_seconds)
    },
    {
      name  = "SP1_DEPOSIT_PROGRAM_URL"
      value = local.shared_sp1_deposit_program_url
    },
    {
      name  = "SP1_WITHDRAW_PROGRAM_URL"
      value = local.shared_sp1_withdraw_program_url
    },
    {
      name  = "SP1_DEPOSIT_PROGRAM_VKEY"
      value = local.shared_deposit_image_id
    },
    {
      name  = "SP1_WITHDRAW_PROGRAM_VKEY"
      value = local.shared_withdraw_image_id
    },
  ]
  shared_proof_funder_environment = [
    {
      name  = "JUNO_QUEUE_KAFKA_TLS"
      value = "true"
    },
    {
      name  = "JUNO_QUEUE_KAFKA_AUTH_MODE"
      value = "aws-msk-iam"
    },
    {
      name  = "JUNO_QUEUE_KAFKA_AWS_REGION"
      value = var.aws_region
    },
    {
      name  = "SP1_NETWORK_RPC_URL"
      value = trimspace(var.shared_sp1_rpc_url)
    },
    {
      name  = "SP1_DEPOSIT_PROGRAM_URL"
      value = local.shared_sp1_deposit_program_url
    },
    {
      name  = "SP1_WITHDRAW_PROGRAM_URL"
      value = local.shared_sp1_withdraw_program_url
    },
    {
      name  = "SP1_DEPOSIT_PROGRAM_VKEY"
      value = local.shared_deposit_image_id
    },
    {
      name  = "SP1_WITHDRAW_PROGRAM_VKEY"
      value = local.shared_withdraw_image_id
    },
  ]

  ipfs_lb_name            = trim(substr("${local.resource_slug}-ipfs", 0, 32), "-")
  ipfs_target_group_name  = trim(substr("${local.resource_slug}-ipfs-api", 0, 32), "-")
  ipfs_launch_name_prefix = trim(substr("${local.resource_slug}-ipfs-", 0, 32), "-")
}

check "distinct_proof_secret_arns" {
  assert {
    condition     = var.shared_sp1_requestor_secret_arn != var.shared_sp1_funder_secret_arn
    error_message = "shared_sp1_requestor_secret_arn and shared_sp1_funder_secret_arn must differ."
  }
}

check "proof_service_image_ecr_scope" {
  assert {
    condition     = local.shared_proof_service_image_override == "" || !local.shared_proof_service_image_uses_ecr || trimspace(var.shared_proof_service_image_ecr_repository_arn) != ""
    error_message = "shared_proof_service_image_ecr_repository_arn must be set when shared_proof_service_image points at an explicit ECR repository."
  }
}

resource "aws_security_group" "ecs" {
  name        = "${local.resource_name}-shared-ecs-sg"
  description = "Security group for intents-juno production shared ECS services"
  vpc_id      = data.aws_vpc.selected.id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "shared" {
  name        = "${local.resource_name}-shared-sg"
  description = "Security group for intents-juno production Aurora and MSK services"
  vpc_id      = data.aws_vpc.selected.id

  ingress {
    description     = "Postgres from shared ECS tasks"
    from_port       = var.shared_postgres_port
    to_port         = var.shared_postgres_port
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  dynamic "ingress" {
    for_each = toset(var.shared_service_client_cidr_blocks)
    content {
      description = "Postgres from shared-service clients"
      from_port   = var.shared_postgres_port
      to_port     = var.shared_postgres_port
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  ingress {
    description     = "MSK IAM bootstrap from shared ECS tasks"
    from_port       = var.shared_kafka_port
    to_port         = var.shared_kafka_port
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  dynamic "ingress" {
    for_each = toset(var.shared_service_client_cidr_blocks)
    content {
      description = "MSK IAM bootstrap from shared-service clients"
      from_port   = var.shared_kafka_port
      to_port     = var.shared_kafka_port
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  ingress {
    description = "MSK broker mesh"
    from_port   = 9092
    to_port     = 9094
    protocol    = "tcp"
    self        = true
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "ipfs" {
  name        = "${local.resource_name}-ipfs-sg"
  description = "Security group for intents-juno production shared IPFS nodes"
  vpc_id      = data.aws_vpc.selected.id

  dynamic "ingress" {
    for_each = toset(local.shared_ipfs_ingress_cidrs)
    content {
      description = "IPFS API from approved client networks"
      from_port   = var.shared_ipfs_api_port
      to_port     = var.shared_ipfs_api_port
      protocol    = "tcp"
      cidr_blocks = [ingress.value]
    }
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_db_subnet_group" "shared" {
  name       = "${local.resource_name}-shared-db"
  subnet_ids = local.shared_subnets

  lifecycle {
    precondition {
      condition     = length(local.shared_subnets) >= 2
      error_message = "production-shared Aurora requires at least two subnets."
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-shared-db"
  })
}

resource "aws_rds_cluster" "shared" {
  cluster_identifier        = "${local.resource_name}-shared-aurora"
  engine                    = "aurora-postgresql"
  database_name             = var.shared_postgres_db
  master_username           = var.shared_postgres_user
  master_password           = var.shared_postgres_password
  port                      = var.shared_postgres_port
  db_subnet_group_name      = aws_db_subnet_group.shared.name
  vpc_security_group_ids    = [aws_security_group.shared.id]
  backup_retention_period   = var.shared_postgres_backup_retention_days
  preferred_backup_window   = var.shared_postgres_preferred_backup_window
  storage_encrypted         = true
  skip_final_snapshot       = false
  final_snapshot_identifier = local.aurora_final_snapshot_identifier
  apply_immediately         = false
  deletion_protection       = true
  copy_tags_to_snapshot     = true

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-shared-aurora"
  })
}

resource "aws_rds_cluster_instance" "shared" {
  for_each = data.aws_subnet.shared

  identifier         = trim(substr("${local.resource_slug}-aurora-${replace(each.value.availability_zone, "-", "")}", 0, 63), "-")
  cluster_identifier = aws_rds_cluster.shared.id
  instance_class     = var.shared_aurora_instance_class
  engine             = aws_rds_cluster.shared.engine
  engine_version     = aws_rds_cluster.shared.engine_version
  availability_zone  = each.value.availability_zone

  apply_immediately            = false
  auto_minor_version_upgrade   = true
  copy_tags_to_snapshot        = true
  performance_insights_enabled = true
  publicly_accessible          = false

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-aurora-${replace(each.value.availability_zone, "-", "")}"
  })
}

resource "aws_msk_configuration" "shared" {
  kafka_versions = [var.shared_msk_kafka_version]
  name           = "${local.resource_slug}-shared-msk-config"

  server_properties = <<-PROPERTIES
    auto.create.topics.enable = false
    default.replication.factor = 2
    min.insync.replicas = 2
  PROPERTIES
}

resource "aws_msk_cluster" "shared" {
  cluster_name           = "${local.resource_name}-shared-msk"
  kafka_version          = var.shared_msk_kafka_version
  number_of_broker_nodes = length(local.shared_subnets)

  configuration_info {
    arn      = aws_msk_configuration.shared.arn
    revision = aws_msk_configuration.shared.latest_revision
  }

  broker_node_group_info {
    instance_type   = var.shared_msk_broker_instance_type
    client_subnets  = local.shared_subnets
    security_groups = [aws_security_group.shared.id]

    storage_info {
      ebs_storage_info {
        volume_size = var.shared_msk_broker_ebs_volume_size_gb
      }
    }
  }

  client_authentication {
    sasl {
      iam = true
    }
    unauthenticated = false
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }

  lifecycle {
    precondition {
      condition     = length(local.shared_subnets) >= 2
      error_message = "production-shared MSK requires at least two subnets."
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-shared-msk"
  })
}

data "aws_iam_policy_document" "ecs_task_execution_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "proof_requestor_execution" {
  name               = "${local.resource_name}-proof-requestor-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role.json
  tags               = local.common_tags
}

resource "aws_iam_role" "proof_funder_execution" {
  name               = "${local.resource_name}-proof-funder-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role.json
  tags               = local.common_tags
}

resource "aws_iam_role" "proof_requestor_task" {
  name               = "${local.resource_name}-proof-requestor-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role.json
  tags               = local.common_tags
}

resource "aws_iam_role" "proof_funder_task" {
  name               = "${local.resource_name}-proof-funder-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "proof_requestor_execution_access" {
  dynamic "statement" {
    for_each = local.shared_proof_service_image_requires_ecr_pull ? [1] : []
    content {
      sid = "AllowECRAuthorizationToken"
      actions = [
        "ecr:GetAuthorizationToken",
      ]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = local.shared_proof_service_image_requires_ecr_pull ? [1] : []
    content {
      sid = "AllowProofRequestorImagePull"
      actions = [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
      ]
      resources = [local.shared_proof_service_ecr_repository_arn]
    }
  }

  statement {
    sid = "AllowProofRequestorLogWrite"
    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]
    resources = [
      trimsuffix(aws_cloudwatch_log_group.proof_requestor.arn, ":*"),
      "${trimsuffix(aws_cloudwatch_log_group.proof_requestor.arn, ":*")}:log-stream:*",
    ]
  }

  statement {
    sid = "AllowProofRequestorSecretRead"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
    ]
    resources = [var.shared_sp1_requestor_secret_arn]
  }
}

data "aws_iam_policy_document" "proof_funder_execution_access" {
  dynamic "statement" {
    for_each = local.shared_proof_service_image_requires_ecr_pull ? [1] : []
    content {
      sid = "AllowECRAuthorizationToken"
      actions = [
        "ecr:GetAuthorizationToken",
      ]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = local.shared_proof_service_image_requires_ecr_pull ? [1] : []
    content {
      sid = "AllowProofFunderImagePull"
      actions = [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
      ]
      resources = [local.shared_proof_service_ecr_repository_arn]
    }
  }

  statement {
    sid = "AllowProofFunderLogWrite"
    actions = [
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:PutLogEvents",
    ]
    resources = [
      trimsuffix(aws_cloudwatch_log_group.proof_funder.arn, ":*"),
      "${trimsuffix(aws_cloudwatch_log_group.proof_funder.arn, ":*")}:log-stream:*",
    ]
  }

  statement {
    sid = "AllowProofFunderSecretRead"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
    ]
    resources = [var.shared_sp1_funder_secret_arn]
  }
}

data "aws_iam_policy_document" "proof_requestor_task_access" {
  statement {
    sid = "AllowMSKConnect"
    actions = [
      "kafka-cluster:Connect",
      "kafka-cluster:DescribeCluster",
      "kafka-cluster:DescribeClusterDynamicConfiguration",
    ]
    resources = [aws_msk_cluster.shared.arn]
  }

  statement {
    sid = "AllowReadProofRequestsTopic"
    actions = [
      "kafka-cluster:DescribeTopic",
      "kafka-cluster:ReadData",
    ]
    resources = ["${local.shared_kafka_topic_arn_prefix}/${local.shared_proof_request_topic}"]
  }

  statement {
    sid = "AllowWriteProofResultsTopic"
    actions = [
      "kafka-cluster:DescribeTopic",
      "kafka-cluster:WriteData",
    ]
    resources = ["${local.shared_kafka_topic_arn_prefix}/${local.shared_proof_result_topic}"]
  }

  statement {
    sid = "AllowWriteProofFailuresTopic"
    actions = [
      "kafka-cluster:DescribeTopic",
      "kafka-cluster:WriteData",
    ]
    resources = ["${local.shared_kafka_topic_arn_prefix}/${local.shared_proof_failure_topic}"]
  }

  statement {
    sid = "AllowReadProofRequestorGroup"
    actions = [
      "kafka-cluster:AlterGroup",
      "kafka-cluster:DescribeGroup",
    ]
    resources = ["${local.shared_kafka_group_arn_prefix}/${local.shared_proof_requestor_group}"]
  }
}

data "aws_iam_policy_document" "proof_funder_task_access" {
  statement {
    sid = "AllowMSKConnect"
    actions = [
      "kafka-cluster:Connect",
      "kafka-cluster:DescribeCluster",
      "kafka-cluster:DescribeClusterDynamicConfiguration",
    ]
    resources = [aws_msk_cluster.shared.arn]
  }

  statement {
    sid = "AllowWriteOpsAlertsTopic"
    actions = [
      "kafka-cluster:DescribeTopic",
      "kafka-cluster:WriteData",
    ]
    resources = ["${local.shared_kafka_topic_arn_prefix}/${local.shared_ops_alert_topic}"]
  }
}

resource "aws_iam_role_policy" "proof_requestor_execution_access" {
  name   = "${local.resource_name}-proof-requestor-exec"
  role   = aws_iam_role.proof_requestor_execution.id
  policy = data.aws_iam_policy_document.proof_requestor_execution_access.json
}

resource "aws_iam_role_policy" "proof_funder_execution_access" {
  name   = "${local.resource_name}-proof-funder-exec"
  role   = aws_iam_role.proof_funder_execution.id
  policy = data.aws_iam_policy_document.proof_funder_execution_access.json
}

resource "aws_iam_role_policy" "proof_requestor_task_access" {
  name   = "${local.resource_name}-proof-requestor-task"
  role   = aws_iam_role.proof_requestor_task.id
  policy = data.aws_iam_policy_document.proof_requestor_task_access.json
}

resource "aws_iam_role_policy" "proof_funder_task_access" {
  name   = "${local.resource_name}-proof-funder-task"
  role   = aws_iam_role.proof_funder_task.id
  policy = data.aws_iam_policy_document.proof_funder_task_access.json
}

resource "aws_ecr_repository" "proof_services" {
  name         = "${local.resource_slug}-proof-services"
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-proof-services"
  })
}

resource "aws_cloudwatch_log_group" "proof_requestor" {
  name              = "/intents-juno/production-shared/${local.resource_name}/proof-requestor"
  retention_in_days = var.shared_log_retention_days
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_group" "proof_funder" {
  name              = "/intents-juno/production-shared/${local.resource_name}/proof-funder"
  retention_in_days = var.shared_log_retention_days
  tags              = local.common_tags
}

resource "aws_ecs_cluster" "shared" {
  name = "${local.resource_name}-shared-ecs"
  tags = local.common_tags
}

resource "aws_ecs_task_definition" "proof_requestor" {
  family                   = "${local.resource_name}-proof-requestor"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.shared_ecs_task_cpu)
  memory                   = tostring(var.shared_ecs_task_memory)
  execution_role_arn       = aws_iam_role.proof_requestor_execution.arn
  task_role_arn            = aws_iam_role.proof_requestor_task.arn

  container_definitions = jsonencode([
    {
      name        = "proof-requestor"
      image       = local.shared_proof_service_image
      essential   = true
      command     = local.shared_proof_requestor_command
      environment = local.shared_proof_requestor_environment
      secrets = [
        {
          name      = "PROOF_REQUESTOR_KEY"
          valueFrom = var.shared_sp1_requestor_secret_arn
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.proof_requestor.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "proof-requestor"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = local.shared_proof_service_image != ""
      error_message = "shared_proof_service_image must resolve to a non-empty value."
    }
    precondition {
      condition     = !local.shared_proof_runtime_enabled || local.shared_sp1_requestor_address != ""
      error_message = "shared_sp1_requestor_address must be set when shared_ecs_desired_count > 0."
    }
    precondition {
      condition     = !local.shared_proof_runtime_enabled || var.shared_base_chain_id > 0
      error_message = "shared_base_chain_id must be > 0 when shared_ecs_desired_count > 0."
    }
    precondition {
      condition     = !local.shared_proof_runtime_enabled || can(regex("^0x[0-9a-f]{64}$", local.shared_deposit_image_id))
      error_message = "shared_deposit_image_id must be a 32-byte hex value when shared_ecs_desired_count > 0."
    }
    precondition {
      condition     = !local.shared_proof_runtime_enabled || can(regex("^0x[0-9a-f]{64}$", local.shared_withdraw_image_id))
      error_message = "shared_withdraw_image_id must be a 32-byte hex value when shared_ecs_desired_count > 0."
    }
  }

  tags = local.common_tags
}

resource "aws_ecs_task_definition" "proof_funder" {
  family                   = "${local.resource_name}-proof-funder"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.shared_ecs_task_cpu)
  memory                   = tostring(var.shared_ecs_task_memory)
  execution_role_arn       = aws_iam_role.proof_funder_execution.arn
  task_role_arn            = aws_iam_role.proof_funder_task.arn

  container_definitions = jsonencode([
    {
      name        = "proof-funder"
      image       = local.shared_proof_service_image
      essential   = true
      command     = local.shared_proof_funder_command
      environment = local.shared_proof_funder_environment
      secrets = [
        {
          name      = "PROOF_FUNDER_KEY"
          valueFrom = var.shared_sp1_funder_secret_arn
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.proof_funder.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "proof-funder"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = local.shared_proof_service_image != ""
      error_message = "shared_proof_service_image must resolve to a non-empty value."
    }
    precondition {
      condition     = !local.shared_proof_runtime_enabled || local.shared_sp1_requestor_address != ""
      error_message = "shared_sp1_requestor_address must be set when shared_ecs_desired_count > 0."
    }
    precondition {
      condition     = !local.shared_proof_runtime_enabled || can(regex("^0x[0-9a-f]{64}$", local.shared_deposit_image_id))
      error_message = "shared_deposit_image_id must be a 32-byte hex value when shared_ecs_desired_count > 0."
    }
    precondition {
      condition     = !local.shared_proof_runtime_enabled || can(regex("^0x[0-9a-f]{64}$", local.shared_withdraw_image_id))
      error_message = "shared_withdraw_image_id must be a 32-byte hex value when shared_ecs_desired_count > 0."
    }
  }

  tags = local.common_tags
}

resource "aws_ecs_service" "proof_requestor" {
  name            = "${local.resource_name}-proof-requestor"
  cluster         = aws_ecs_cluster.shared.id
  task_definition = aws_ecs_task_definition.proof_requestor.arn
  desired_count   = var.shared_ecs_desired_count
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = local.shared_subnets
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = var.shared_ecs_assign_public_ip
  }

  depends_on = [aws_iam_role_policy.proof_requestor_execution_access, aws_iam_role_policy.proof_requestor_task_access]
  tags       = local.common_tags
}

resource "aws_ecs_service" "proof_funder" {
  name            = "${local.resource_name}-proof-funder"
  cluster         = aws_ecs_cluster.shared.id
  task_definition = aws_ecs_task_definition.proof_funder.arn
  desired_count   = var.shared_ecs_desired_count
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 100
  deployment_maximum_percent         = 200

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  network_configuration {
    subnets          = local.shared_subnets
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = var.shared_ecs_assign_public_ip
  }

  depends_on = [aws_iam_role_policy.proof_funder_execution_access, aws_iam_role_policy.proof_funder_task_access]
  tags       = local.common_tags
}

resource "aws_lb" "ipfs" {
  name               = local.ipfs_lb_name
  internal           = true
  load_balancer_type = "network"
  subnets            = local.shared_subnets

  lifecycle {
    precondition {
      condition     = length(local.shared_subnets) >= 2
      error_message = "production-shared IPFS NLB requires at least two subnets."
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-ipfs"
  })
}

resource "aws_lb_target_group" "ipfs_api" {
  name        = local.ipfs_target_group_name
  port        = var.shared_ipfs_api_port
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = data.aws_vpc.selected.id

  health_check {
    protocol = "TCP"
    port     = tostring(var.shared_ipfs_api_port)
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-ipfs-api"
  })
}

resource "aws_lb_listener" "ipfs_api" {
  load_balancer_arn = aws_lb.ipfs.arn
  port              = var.shared_ipfs_api_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ipfs_api.arn
  }
}

data "aws_iam_policy_document" "ipfs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ipfs" {
  name               = "${local.resource_name}-ipfs-role"
  assume_role_policy = data.aws_iam_policy_document.ipfs_assume_role.json
  tags               = local.common_tags
}

resource "aws_iam_instance_profile" "ipfs" {
  name = "${local.resource_name}-ipfs-profile"
  role = aws_iam_role.ipfs.name
}

resource "aws_launch_template" "ipfs" {
  name_prefix   = local.ipfs_launch_name_prefix
  image_id      = local.ipfs_ami_id
  instance_type = var.shared_ipfs_instance_type

  iam_instance_profile {
    name = aws_iam_instance_profile.ipfs.name
  }

  network_interfaces {
    associate_public_ip_address = var.shared_ipfs_assign_public_ip
    security_groups             = [aws_security_group.ipfs.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.shared_ipfs_root_volume_size_gb
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }

  user_data = base64encode(<<-EOF
    #!/usr/bin/env bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y ca-certificates curl docker.io
    systemctl enable --now docker

    docker rm -f intents-shared-ipfs >/dev/null 2>&1 || true
    docker pull ${var.shared_ipfs_container_image}
    docker run -d \
      --name intents-shared-ipfs \
      --restart unless-stopped \
      -p ${var.shared_ipfs_api_port}:5001 \
      ${var.shared_ipfs_container_image} daemon --migrate=true --api /ip4/0.0.0.0/tcp/5001 --routing=dhtclient
  EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${local.resource_name}-ipfs"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      Name = "${local.resource_name}-ipfs"
    })
  }
}

resource "aws_autoscaling_group" "ipfs" {
  name                = "${local.resource_name}-ipfs"
  min_size            = var.shared_ipfs_min_size
  max_size            = var.shared_ipfs_max_size
  desired_capacity    = var.shared_ipfs_desired_capacity
  vpc_zone_identifier = local.shared_subnets
  target_group_arns   = [aws_lb_target_group.ipfs_api.arn]

  health_check_type         = "ELB"
  health_check_grace_period = 120
  default_cooldown          = 120

  launch_template {
    id      = aws_launch_template.ipfs.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${local.resource_name}-ipfs"
    propagate_at_launch = true
  }

  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    precondition {
      condition     = var.shared_ipfs_min_size >= 2
      error_message = "shared_ipfs_min_size must be at least 2 to avoid a single-node IPFS deployment."
    }
    precondition {
      condition     = var.shared_ipfs_desired_capacity >= var.shared_ipfs_min_size && var.shared_ipfs_desired_capacity <= var.shared_ipfs_max_size
      error_message = "shared_ipfs_desired_capacity must be between shared_ipfs_min_size and shared_ipfs_max_size."
    }
  }
}
