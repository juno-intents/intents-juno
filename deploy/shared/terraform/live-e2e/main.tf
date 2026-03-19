provider "aws" {
  region = var.aws_region
}

provider "aws" {
  alias  = "dr"
  region = var.shared_postgres_dr_region
}

locals {
  resource_name = "${var.name_prefix}-${var.deployment_id}"

  common_tags = {
    Project    = "intents-juno"
    ManagedBy  = "terraform"
    Stack      = "live-e2e"
    Deployment = var.deployment_id
  }
}

data "aws_subnets" "selected_vpc" {
  dynamic "filter" {
    for_each = var.vpc_id == "" ? [] : [var.vpc_id]
    content {
      name   = "vpc-id"
      values = [filter.value]
    }
  }
}

locals {
  bootstrap_subnet_id = var.subnet_id != "" ? var.subnet_id : data.aws_subnets.selected_vpc.ids[0]
}

data "aws_subnet" "bootstrap" {
  id = local.bootstrap_subnet_id
}

locals {
  selected_vpc_id = var.vpc_id != "" ? var.vpc_id : data.aws_subnet.bootstrap.vpc_id
}

data "aws_vpc" "selected" {
  id = local.selected_vpc_id
}

data "aws_subnets" "shared_vpc" {
  filter {
    name   = "vpc-id"
    values = [local.selected_vpc_id]
  }
}

# Look up each subnet to get its AZ, so we can pick one per AZ.
data "aws_subnet" "all_vpc" {
  for_each = toset(data.aws_subnets.shared_vpc.ids)
  id       = each.value
}

locals {
  public_subnets_by_az = {
    for s in data.aws_subnet.all_vpc :
    s.availability_zone => s.id...
    if s.map_public_ip_on_launch
  }
  public_one_per_az = sort([for az, ids in local.public_subnets_by_az : sort(ids)[0]])

  # Group private subnets by AZ, pick one private subnet per AZ (sorted for determinism).
  private_subnets_by_az = {
    for s in data.aws_subnet.all_vpc :
    s.availability_zone => s.id...
    if !s.map_public_ip_on_launch
  }
  private_one_per_az = sort([for az, ids in local.private_subnets_by_az : sort(ids)[0]])

  selected_subnet_id = var.subnet_id != "" ? var.subnet_id : local.public_one_per_az[0]
  shared_subnets = length(var.shared_subnet_ids) > 0 ? sort(var.shared_subnet_ids) : (
    length(local.private_one_per_az) >= 2 ? slice(local.private_one_per_az, 0, 2) : local.private_one_per_az
  )
}

data "aws_subnet" "selected" {
  id = local.selected_subnet_id
}

check "runner_operator_public_subnet_default" {
  assert {
    condition     = var.subnet_id != "" || length(local.public_one_per_az) > 0
    error_message = "runner/operator hosts require at least one public subnet unless subnet_id is set explicitly."
  }
}

data "aws_subnet" "shared" {
  for_each = var.provision_shared_services ? toset(local.shared_subnets) : toset([])
  id       = each.value
}

data "aws_route_table" "shared" {
  for_each  = var.provision_shared_services ? toset(local.shared_subnets) : toset([])
  subnet_id = each.value
}

check "shared_ecs_private_subnets_when_no_public_ip" {
  assert {
    condition = !var.provision_shared_services || var.shared_ecs_assign_public_ip || alltrue([
      for subnet in data.aws_subnet.shared : !subnet.map_public_ip_on_launch
    ])
    error_message = "shared proof services require private shared_subnet_ids when shared_ecs_assign_public_ip=false."
  }
}

check "shared_wireguard_inputs_when_enabled" {
  assert {
    condition = !local.wireguard_enabled || (
      (trimspace(var.shared_wireguard_public_subnet_id) != "" || length(local.public_one_per_az) > 0) &&
      trimspace(var.shared_wireguard_backoffice_hostname) != "" &&
      (
        trimspace(var.shared_wireguard_backoffice_private_endpoint) == "" ||
        can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}$", trimspace(var.shared_wireguard_backoffice_private_endpoint)))
      )
    )
    error_message = "shared wireguard requires a public subnet, shared_wireguard_backoffice_hostname, and an IPv4 shared_wireguard_backoffice_private_endpoint when an explicit endpoint override is set."
  }
}

locals {
  shared_subnet_cidrs    = [for subnet in data.aws_subnet.shared : subnet.cidr_block]
  shared_route_table_ids = sort(distinct([for route_table in data.aws_route_table.shared : route_table.id]))
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

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
  runner_ami_id   = var.runner_ami_id != "" ? var.runner_ami_id : data.aws_ami.ubuntu.id
  operator_ami_id = var.operator_ami_id != "" ? var.operator_ami_id : data.aws_ami.ubuntu.id
  shared_ami_id   = var.shared_ami_id != "" ? var.shared_ami_id : data.aws_ami.ubuntu.id

  dkg_bucket_base = trim(replace(lower(local.resource_name), "_", "-"), "-")
  dkg_bucket_name = trim(substr("${local.dkg_bucket_base}-dkgpk", 0, 63), "-")

  managed_instance_profile_enabled = var.iam_instance_profile == ""
  instance_profile_name            = local.managed_instance_profile_enabled ? aws_iam_instance_profile.live_e2e[0].name : var.iam_instance_profile
  allowed_checkpoint_signer_kms_key_arns = sort(distinct(concat(
    [aws_kms_key.dkg.arn],
    [
      for arn in var.allowed_checkpoint_signer_kms_key_arns : trimspace(arn)
      if trimspace(arn) != ""
    ]
  )))

  resource_slug                  = trim(replace(lower(local.resource_name), "_", "-"), "-")
  ipfs_lb_name                   = trim(substr("${local.resource_slug}-ipfs", 0, 32), "-")
  ipfs_target_group_name         = trim(substr("${local.resource_slug}-ipfstg", 0, 32), "-")
  ipfs_launch_name_prefix        = trim(substr("${local.resource_slug}-ipfs-", 0, 32), "-")
  wireguard_enabled              = var.provision_shared_services && var.shared_wireguard_enabled
  wireguard_public_subnet_id     = local.wireguard_enabled ? (trimspace(var.shared_wireguard_public_subnet_id) != "" ? trimspace(var.shared_wireguard_public_subnet_id) : (length(local.public_one_per_az) > 0 ? local.public_one_per_az[0] : "")) : ""
  wireguard_network_prefix       = tonumber(split("/", var.shared_wireguard_network_cidr)[1])
  wireguard_gateway_tunnel_ip    = local.wireguard_enabled ? cidrhost(var.shared_wireguard_network_cidr, 1) : ""
  wireguard_gateway_address_cidr = local.wireguard_enabled ? "${local.wireguard_gateway_tunnel_ip}/${local.wireguard_network_prefix}" : ""
  wireguard_client_tunnel_ip     = local.wireguard_enabled ? cidrhost(var.shared_wireguard_network_cidr, 2) : ""
  wireguard_client_address_cidr  = local.wireguard_enabled ? "${local.wireguard_client_tunnel_ip}/32" : ""
  wireguard_backoffice_private_endpoint = local.wireguard_enabled ? (
    trimspace(var.shared_wireguard_backoffice_private_endpoint) != "" ? trimspace(var.shared_wireguard_backoffice_private_endpoint) : aws_instance.runner.private_ip
  ) : ""
}

resource "aws_kms_key" "dkg" {
  description             = "Live e2e DKG key package envelope key"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-dkg-kms"
  })
}

resource "aws_kms_alias" "dkg" {
  name          = "alias/${local.resource_name}-dkg"
  target_key_id = aws_kms_key.dkg.key_id
}

resource "aws_s3_bucket" "dkg_keypackages" {
  bucket        = local.dkg_bucket_name
  force_destroy = true

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-dkg-keypackages"
  })
}

resource "aws_s3_bucket_public_access_block" "dkg_keypackages" {
  bucket = aws_s3_bucket.dkg_keypackages.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "dkg_keypackages" {
  bucket = aws_s3_bucket.dkg_keypackages.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "dkg_keypackages" {
  bucket = aws_s3_bucket.dkg_keypackages.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.dkg.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "random_password" "shared_ipfs_api_bearer_token" {
  count = var.provision_shared_services ? 1 : 0

  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "shared_ipfs_api_bearer_token" {
  count = var.provision_shared_services ? 1 : 0

  name = "${local.resource_name}-shared-ipfs-api-bearer-token"
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "shared_ipfs_api_bearer_token" {
  count = var.provision_shared_services ? 1 : 0

  secret_id     = aws_secretsmanager_secret.shared_ipfs_api_bearer_token[0].id
  secret_string = random_password.shared_ipfs_api_bearer_token[0].result
}

resource "random_password" "shared_kafka_critical_hmac_key" {
  count = var.provision_shared_services ? 1 : 0

  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "shared_kafka_critical_hmac_key" {
  count = var.provision_shared_services ? 1 : 0

  name = "${local.resource_name}-shared-kafka-critical-hmac-key"
  tags = local.common_tags
}

resource "aws_secretsmanager_secret_version" "shared_kafka_critical_hmac_key" {
  count = var.provision_shared_services ? 1 : 0

  secret_id     = aws_secretsmanager_secret.shared_kafka_critical_hmac_key[0].id
  secret_string = random_password.shared_kafka_critical_hmac_key[0].result
}

data "aws_iam_policy_document" "live_e2e_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "live_e2e" {
  count = local.managed_instance_profile_enabled ? 1 : 0

  name               = "${local.resource_name}-instance-role"
  assume_role_policy = data.aws_iam_policy_document.live_e2e_assume_role.json

  tags = local.common_tags
}

locals {
  live_e2e_inline_policy_statements = concat(
    [
      {
        Sid    = "AllowDKGBucketList"
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.dkg_keypackages.arn
        ]
      },
      {
        Sid    = "AllowDKGBucketObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:AbortMultipartUpload",
          "s3:ListBucketMultipartUploads",
          "s3:ListMultipartUploadParts"
        ]
        Resource = [
          "${aws_s3_bucket.dkg_keypackages.arn}/*"
        ]
      },
      {
        Sid    = "AllowDKGKMS"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = [
          aws_kms_key.dkg.arn
        ]
      },
      {
        Sid    = "AllowCheckpointSignerKMS"
        Effect = "Allow"
        Action = [
          "kms:DescribeKey",
          "kms:GetPublicKey",
          "kms:Sign"
        ]
        Resource = local.allowed_checkpoint_signer_kms_key_arns
      }
    ],
    [
      for statement_json in(
        var.provision_shared_services ? [
          jsonencode({
            Sid    = "AllowSharedMSKConnect"
            Effect = "Allow"
            Action = [
              "kafka-cluster:Connect",
              "kafka-cluster:DescribeCluster",
              "kafka-cluster:DescribeClusterDynamicConfiguration"
            ]
            Resource = [local.shared_kafka_cluster_arn]
          }),
          jsonencode({
            Sid    = "AllowSharedMSKTopicAccess"
            Effect = "Allow"
            Action = [
              "kafka-cluster:CreateTopic",
              "kafka-cluster:DescribeTopic",
              "kafka-cluster:DescribeTopicDynamicConfiguration",
              "kafka-cluster:AlterTopic",
              "kafka-cluster:ReadData",
              "kafka-cluster:WriteData",
              "kafka-cluster:WriteDataIdempotently"
            ]
            Resource = ["${local.shared_kafka_topic_arn_prefix}/*"]
          }),
          jsonencode({
            Sid    = "AllowSharedMSKGroupAccess"
            Effect = "Allow"
            Action = [
              "kafka-cluster:AlterGroup",
              "kafka-cluster:DescribeGroup"
            ]
            Resource = ["${local.shared_kafka_group_arn_prefix}/*"]
          }),
          jsonencode({
            Sid    = "AllowSharedECSServiceRollout"
            Effect = "Allow"
            Action = [
              "ecs:DescribeClusters",
              "ecs:DescribeServices",
              "ecs:DescribeTaskDefinition",
              "ecs:RegisterTaskDefinition",
              "ecs:UpdateService"
            ]
            Resource = "*"
          }),
          jsonencode({
            Sid    = "AllowPassSharedECSTaskExecutionRole"
            Effect = "Allow"
            Action = [
              "iam:PassRole"
            ]
            Resource = [
              aws_iam_role.ecs_task_execution[0].arn
            ]
            Condition = {
              StringEquals = {
                "iam:PassedToService" = "ecs-tasks.amazonaws.com"
              }
            }
          }),
          jsonencode({
            Sid    = "AllowSharedECSLogTail"
            Effect = "Allow"
            Action = [
              "logs:DescribeLogGroups",
              "logs:DescribeLogStreams",
              "logs:FilterLogEvents",
              "logs:GetLogEvents"
            ]
            Resource = "*"
          }),
          jsonencode({
            Sid    = "AllowSharedIPFSSecretRead"
            Effect = "Allow"
            Action = [
              "secretsmanager:DescribeSecret",
              "secretsmanager:GetSecretValue"
            ]
            Resource = [aws_secretsmanager_secret.shared_ipfs_api_bearer_token[0].arn]
          })
        ] : []
      ) : jsondecode(statement_json)
    ]
  )
}

resource "aws_iam_role_policy" "live_e2e_inline" {
  count = local.managed_instance_profile_enabled ? 1 : 0

  name = "${local.resource_name}-instance-inline"
  role = aws_iam_role.live_e2e[0].id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.live_e2e_inline_policy_statements
  })
}

resource "aws_iam_instance_profile" "live_e2e" {
  count = local.managed_instance_profile_enabled ? 1 : 0

  name = "${local.resource_name}-instance-profile"
  role = aws_iam_role.live_e2e[0].name
}

resource "aws_key_pair" "runner" {
  key_name   = "${local.resource_name}-ssh"
  public_key = trimspace(var.ssh_public_key)

  tags = local.common_tags
}

resource "aws_security_group" "runner" {
  name        = "${local.resource_name}-sg"
  description = "Security group for intents-juno live e2e runner"
  vpc_id      = local.selected_vpc_id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  ingress {
    description = "HTTPS for bridge origin and direct app access"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "IPFS API from VPC (runner hosts IPFS container as NLB target)"
    from_port   = 5001
    to_port     = 5001
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
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

resource "aws_security_group" "ecs" {
  count = var.provision_shared_services ? 1 : 0

  name        = "${local.resource_name}-shared-ecs-sg"
  description = "Security group for intents-juno live e2e ECS shared services"
  vpc_id      = local.selected_vpc_id

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_security_group" "shared_vpc_endpoints" {
  count = var.provision_shared_services ? 1 : 0

  name        = "${local.resource_name}-shared-vpce-sg"
  description = "Security group for intents-juno live e2e shared VPC interface endpoints"
  vpc_id      = local.selected_vpc_id

  ingress {
    description = "HTTPS from the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.selected.cidr_block]
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

resource "aws_security_group" "shared" {
  count = var.provision_shared_services ? 1 : 0

  name        = "${local.resource_name}-shared-sg"
  description = "Security group for intents-juno live e2e Aurora/MSK shared services"
  vpc_id      = local.selected_vpc_id

  ingress {
    description = "Postgres from runner"
    from_port   = var.shared_postgres_port
    to_port     = var.shared_postgres_port
    protocol    = "tcp"
    security_groups = compact([
      aws_security_group.runner.id,
      aws_security_group.operator.id,
      try(aws_security_group.ecs[0].id, "")
    ])
  }

  ingress {
    description = "Kafka from runner"
    from_port   = var.shared_kafka_port
    to_port     = var.shared_kafka_port
    protocol    = "tcp"
    security_groups = compact([
      aws_security_group.runner.id,
      aws_security_group.operator.id,
      try(aws_security_group.ecs[0].id, "")
    ])
  }

  ingress {
    description = "MSK broker mesh"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
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
  count = var.provision_shared_services ? 1 : 0

  name        = "${local.resource_name}-ipfs-sg"
  description = "Security group for intents-juno live e2e IPFS pinning ASG"
  vpc_id      = local.selected_vpc_id

  ingress {
    description = "IPFS API from runner"
    from_port   = var.shared_ipfs_api_port
    to_port     = var.shared_ipfs_api_port
    protocol    = "tcp"
    security_groups = [
      aws_security_group.runner.id,
      aws_security_group.operator.id
    ]
  }

  ingress {
    description = "IPFS API from shared subnets for NLB target health checks"
    from_port   = var.shared_ipfs_api_port
    to_port     = var.shared_ipfs_api_port
    protocol    = "tcp"
    cidr_blocks = local.shared_subnet_cidrs
  }

  ingress {
    description = "IPFS API from operator/runner subnet (NLB preserves client IPs)"
    from_port   = var.shared_ipfs_api_port
    to_port     = var.shared_ipfs_api_port
    protocol    = "tcp"
    cidr_blocks = [data.aws_subnet.selected.cidr_block]
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

resource "aws_security_group" "operator" {
  name        = "${local.resource_name}-operator-sg"
  description = "Security group for intents-juno live e2e operator hosts"
  vpc_id      = local.selected_vpc_id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  ingress {
    description     = "SSH from runner"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.runner.id]
  }

  ingress {
    description     = "Operator gRPC from runner"
    from_port       = var.operator_base_port
    to_port         = var.operator_base_port + var.operator_instance_count - 1
    protocol        = "tcp"
    security_groups = [aws_security_group.runner.id]
  }

  ingress {
    description     = "Relayer health ports from runner"
    from_port       = 18301
    to_port         = 18310
    protocol        = "tcp"
    security_groups = [aws_security_group.runner.id]
  }

  ingress {
    description     = "Base-relayer listen port from runner"
    from_port       = var.operator_base_port + 1200
    to_port         = var.operator_base_port + 1200
    protocol        = "tcp"
    security_groups = [aws_security_group.runner.id]
  }

  ingress {
    description     = "Juno RPC from runner"
    from_port       = 18232
    to_port         = 18232
    protocol        = "tcp"
    security_groups = [aws_security_group.runner.id]
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

resource "aws_security_group_rule" "operator_grpc_mesh_ingress" {
  type                     = "ingress"
  description              = "Operator gRPC from operators"
  from_port                = var.operator_base_port
  to_port                  = var.operator_base_port + var.operator_instance_count - 1
  protocol                 = "tcp"
  security_group_id        = aws_security_group.operator.id
  source_security_group_id = aws_security_group.operator.id
}

resource "aws_db_subnet_group" "shared" {
  count = var.provision_shared_services ? 1 : 0

  name       = "${local.resource_name}-shared-db"
  subnet_ids = local.shared_subnets

  lifecycle {
    precondition {
      condition     = length(local.shared_subnets) >= 2
      error_message = "Shared Aurora/MSK resources require at least two subnets in distinct AZs."
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-shared-db"
  })
}

resource "aws_rds_cluster" "shared" {
  count = var.provision_shared_services ? 1 : 0

  cluster_identifier      = "${local.resource_name}-shared-aurora"
  engine                  = "aurora-postgresql"
  database_name           = var.shared_postgres_db
  master_username         = var.shared_postgres_user
  master_password         = var.shared_postgres_password
  port                    = var.shared_postgres_port
  db_subnet_group_name    = aws_db_subnet_group.shared[0].name
  vpc_security_group_ids  = [aws_security_group.shared[0].id]
  backup_retention_period = 1
  preferred_backup_window = "07:00-09:00"
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.dkg.arn
  skip_final_snapshot     = true
  apply_immediately       = true
  deletion_protection     = false

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-shared-aurora"
  })
}

resource "aws_rds_cluster_instance" "shared" {
  for_each = var.provision_shared_services ? data.aws_subnet.shared : {}

  identifier         = trim(substr("${local.resource_name}-aurora-${replace(each.value.availability_zone, "-", "")}", 0, 63), "-")
  cluster_identifier = aws_rds_cluster.shared[0].id
  instance_class     = var.shared_aurora_instance_class
  engine             = aws_rds_cluster.shared[0].engine
  engine_version     = aws_rds_cluster.shared[0].engine_version
  availability_zone  = each.value.availability_zone

  apply_immediately            = true
  auto_minor_version_upgrade   = true
  copy_tags_to_snapshot        = true
  performance_insights_enabled = false
  publicly_accessible          = false

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-aurora-${replace(each.value.availability_zone, "-", "")}"
  })
}

data "aws_iam_policy_document" "shared_backup_assume_role" {
  count = var.provision_shared_services ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "shared_backup" {
  count = var.provision_shared_services ? 1 : 0

  name               = "${local.resource_name}-backup-role"
  assume_role_policy = data.aws_iam_policy_document.shared_backup_assume_role[0].json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "shared_backup_backup" {
  count = var.provision_shared_services ? 1 : 0

  role       = aws_iam_role.shared_backup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "shared_backup_restore" {
  count = var.provision_shared_services ? 1 : 0

  role       = aws_iam_role.shared_backup[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

resource "aws_backup_vault" "shared_postgres" {
  count = var.provision_shared_services ? 1 : 0

  name = "${local.resource_name}-shared-postgres"

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-shared-postgres-backup"
  })
}

resource "aws_backup_vault" "shared_postgres_dr" {
  count    = var.provision_shared_services ? 1 : 0
  provider = aws.dr
  name     = "${local.resource_name}-shared-postgres-dr"

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-shared-postgres-backup-dr"
  })
}

resource "aws_backup_plan" "shared_postgres" {
  count = var.provision_shared_services ? 1 : 0

  name = "${local.resource_name}-shared-postgres"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.shared_postgres[0].name
    schedule          = var.shared_postgres_backup_schedule_expression

    lifecycle {
      delete_after = var.shared_postgres_backup_delete_after_days
    }

    copy_action {
      destination_vault_arn = aws_backup_vault.shared_postgres_dr[0].arn

      lifecycle {
        delete_after = var.shared_postgres_backup_delete_after_days
      }
    }
  }

  tags = local.common_tags
}

resource "aws_backup_selection" "shared_postgres" {
  count = var.provision_shared_services ? 1 : 0

  iam_role_arn = aws_iam_role.shared_backup[0].arn
  name         = "${local.resource_name}-shared-postgres"
  plan_id      = aws_backup_plan.shared_postgres[0].id
  resources    = [aws_rds_cluster.shared[0].arn]
}

resource "aws_msk_configuration" "shared" {
  count = var.provision_shared_services ? 1 : 0

  kafka_versions = [var.shared_msk_kafka_version]
  name           = "${local.resource_slug}-shared-msk-config"

  server_properties = <<-PROPERTIES
    auto.create.topics.enable = true
    default.replication.factor = 2
    min.insync.replicas = 1
  PROPERTIES
}

resource "aws_msk_cluster" "shared" {
  count = var.provision_shared_services ? 1 : 0

  cluster_name           = "${local.resource_name}-shared-msk"
  kafka_version          = var.shared_msk_kafka_version
  number_of_broker_nodes = length(local.shared_subnets)

  configuration_info {
    arn      = aws_msk_configuration.shared[0].arn
    revision = aws_msk_configuration.shared[0].latest_revision
  }

  broker_node_group_info {
    instance_type   = var.shared_msk_broker_instance_type
    client_subnets  = local.shared_subnets
    security_groups = [aws_security_group.shared[0].id]

    storage_info {
      ebs_storage_info {
        volume_size = var.shared_msk_broker_ebs_volume_size_gb
      }
    }

    connectivity_info {
      vpc_connectivity {
        client_authentication {
          sasl {
            iam = true
          }
        }
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
      error_message = "MSK requires at least two subnets in distinct AZs for live e2e shared services."
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

resource "aws_iam_role" "ecs_task_execution" {
  count = var.provision_shared_services ? 1 : 0

  name               = "${local.resource_name}-ecs-task-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role.json

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "ecs_task_execution" {
  count = var.provision_shared_services ? 1 : 0

  role       = aws_iam_role.ecs_task_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "proof_requestor_task" {
  count = var.provision_shared_services ? 1 : 0

  name               = "${local.resource_name}-proof-requestor-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role.json

  tags = local.common_tags
}

resource "aws_iam_role" "proof_funder_task" {
  count = var.provision_shared_services ? 1 : 0

  name               = "${local.resource_name}-proof-funder-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_execution_assume_role.json

  tags = local.common_tags
}

resource "aws_ecr_repository" "proof_services" {
  count = var.provision_shared_services ? 1 : 0

  name         = "${local.resource_slug}-proof-services"
  force_delete = true

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-proof-services"
  })
}

locals {
  shared_proof_service_image         = trimspace(var.shared_proof_service_image)
  shared_sp1_requestor_secret_arn    = trimspace(var.shared_sp1_requestor_secret_arn)
  shared_sp1_funder_secret_arn       = trimspace(var.shared_sp1_funder_secret_arn)
  shared_sp1_requestor_address       = trimspace(var.shared_sp1_requestor_address)
  shared_proof_runtime_enabled       = var.shared_ecs_desired_count > 0
  shared_proof_guest_release_tag     = trimspace(var.shared_bridge_guest_release_tag)
  shared_deposit_image_id            = lower(trimspace(var.shared_deposit_image_id))
  shared_withdraw_image_id           = lower(trimspace(var.shared_withdraw_image_id))
  shared_deposit_image_id_hex        = replace(local.shared_deposit_image_id, "0x", "")
  shared_withdraw_image_id_hex       = replace(local.shared_withdraw_image_id, "0x", "")
  shared_postgres_dsn                = format("postgres://%s:%s@%s:%d/%s?sslmode=require", urlencode(var.shared_postgres_user), urlencode(var.shared_postgres_password), try(aws_rds_cluster.shared[0].endpoint, ""), var.shared_postgres_port, urlencode(var.shared_postgres_db))
  shared_kafka_cluster_arn           = length(aws_msk_cluster.shared) > 0 ? aws_msk_cluster.shared[0].arn : ""
  shared_kafka_bootstrap_brokers     = length(aws_msk_cluster.shared) > 0 ? aws_msk_cluster.shared[0].bootstrap_brokers_sasl_iam : ""
  shared_kafka_topic_arn_prefix      = replace(local.shared_kafka_cluster_arn, ":cluster/", ":topic/")
  shared_kafka_group_arn_prefix      = replace(local.shared_kafka_cluster_arn, ":cluster/", ":group/")
  shared_proof_request_topic         = "proof.requests.v1"
  shared_proof_result_topic          = "proof.fulfillments.v1"
  shared_proof_failure_topic         = "proof.failures.v1"
  shared_ops_alert_topic             = "ops.alerts.v1"
  shared_proof_requestor_group       = "proof-requestor"
  shared_sp1_projected_pair_cost_wei = (var.shared_sp1_groth16_base_fee_wei * 2) + (var.shared_sp1_max_price_per_pgu * (var.shared_sp1_deposit_pgu_estimate + var.shared_sp1_withdraw_pgu_estimate))
  shared_sp1_projected_with_overhead = floor(((local.shared_sp1_projected_pair_cost_wei * 120) + 99) / 100)
  shared_sp1_required_credit_buffer  = local.shared_sp1_projected_with_overhead * 3
  shared_sp1_deposit_program_url     = can(regex("^0x[0-9a-f]{64}$", local.shared_deposit_image_id)) ? format("https://github.com/juno-intents/intents-juno/releases/download/%s/deposit-guest-%s.elf", local.shared_proof_guest_release_tag, local.shared_deposit_image_id_hex) : ""
  shared_sp1_withdraw_program_url    = can(regex("^0x[0-9a-f]{64}$", local.shared_withdraw_image_id)) ? format("https://github.com/juno-intents/intents-juno/releases/download/%s/withdraw-guest-%s.elf", local.shared_proof_guest_release_tag, local.shared_withdraw_image_id_hex) : ""
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
}

data "aws_iam_policy_document" "ecs_task_execution_secrets" {
  count = var.provision_shared_services && (local.shared_sp1_requestor_secret_arn != "" || local.shared_sp1_funder_secret_arn != "") ? 1 : 0

  statement {
    sid = "AllowProofServiceSecretRead"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = compact([
      local.shared_sp1_requestor_secret_arn,
      local.shared_sp1_funder_secret_arn,
    ])
  }
}

data "aws_iam_policy_document" "proof_requestor_task_access" {
  count = var.provision_shared_services ? 1 : 0

  statement {
    sid = "AllowMSKConnect"
    actions = [
      "kafka-cluster:Connect",
      "kafka-cluster:DescribeCluster",
      "kafka-cluster:DescribeClusterDynamicConfiguration",
    ]
    resources = [local.shared_kafka_cluster_arn]
  }

  statement {
    sid = "AllowMSKTopicAccess"
    actions = [
      "kafka-cluster:CreateTopic",
      "kafka-cluster:DescribeTopic",
      "kafka-cluster:DescribeTopicDynamicConfiguration",
      "kafka-cluster:AlterTopic",
      "kafka-cluster:ReadData",
      "kafka-cluster:WriteData",
      "kafka-cluster:WriteDataIdempotently",
    ]
    resources = ["${local.shared_kafka_topic_arn_prefix}/*"]
  }

  statement {
    sid = "AllowMSKGroupAccess"
    actions = [
      "kafka-cluster:AlterGroup",
      "kafka-cluster:DescribeGroup",
    ]
    resources = ["${local.shared_kafka_group_arn_prefix}/*"]
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
  count = var.provision_shared_services ? 1 : 0

  statement {
    sid = "AllowMSKConnect"
    actions = [
      "kafka-cluster:Connect",
      "kafka-cluster:DescribeCluster",
      "kafka-cluster:DescribeClusterDynamicConfiguration",
    ]
    resources = [local.shared_kafka_cluster_arn]
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

resource "aws_iam_role_policy" "ecs_task_execution_secrets" {
  count = var.provision_shared_services && (local.shared_sp1_requestor_secret_arn != "" || local.shared_sp1_funder_secret_arn != "") ? 1 : 0

  name   = "${local.resource_name}-ecs-task-exec-secrets"
  role   = aws_iam_role.ecs_task_execution[0].id
  policy = data.aws_iam_policy_document.ecs_task_execution_secrets[0].json
}

resource "aws_iam_role_policy" "proof_requestor_task_access" {
  count = var.provision_shared_services ? 1 : 0

  name   = "${local.resource_name}-proof-requestor-task"
  role   = aws_iam_role.proof_requestor_task[0].id
  policy = data.aws_iam_policy_document.proof_requestor_task_access[0].json
}

resource "aws_iam_role_policy" "proof_funder_task_access" {
  count = var.provision_shared_services ? 1 : 0

  name   = "${local.resource_name}-proof-funder-task"
  role   = aws_iam_role.proof_funder_task[0].id
  policy = data.aws_iam_policy_document.proof_funder_task_access[0].json
}

resource "aws_cloudwatch_log_group" "proof_requestor" {
  count = var.provision_shared_services ? 1 : 0

  name              = "/intents-juno/live-e2e/${local.resource_name}/proof-requestor"
  retention_in_days = 7

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "proof_funder" {
  count = var.provision_shared_services ? 1 : 0

  name              = "/intents-juno/live-e2e/${local.resource_name}/proof-funder"
  retention_in_days = 7

  tags = local.common_tags
}

resource "aws_ecs_cluster" "shared" {
  count = var.provision_shared_services ? 1 : 0

  name = "${local.resource_name}-shared-ecs"

  tags = local.common_tags
}

resource "aws_vpc_endpoint" "secretsmanager" {
  count = var.provision_shared_services ? 1 : 0

  vpc_id              = local.selected_vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.secretsmanager"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.shared_subnets
  security_group_ids  = [aws_security_group.shared_vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-secretsmanager-vpce"
  })
}

resource "aws_vpc_endpoint" "ecr_api" {
  count = var.provision_shared_services ? 1 : 0

  vpc_id              = local.selected_vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.shared_subnets
  security_group_ids  = [aws_security_group.shared_vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-ecr-api-vpce"
  })
}

resource "aws_vpc_endpoint" "ecr_dkr" {
  count = var.provision_shared_services ? 1 : 0

  vpc_id              = local.selected_vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.shared_subnets
  security_group_ids  = [aws_security_group.shared_vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-ecr-dkr-vpce"
  })
}

resource "aws_vpc_endpoint" "sts" {
  count = var.provision_shared_services ? 1 : 0

  vpc_id              = local.selected_vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.sts"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.shared_subnets
  security_group_ids  = [aws_security_group.shared_vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-sts-vpce"
  })
}

resource "aws_vpc_endpoint" "kms" {
  count = var.provision_shared_services ? 1 : 0

  vpc_id              = local.selected_vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.kms"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.shared_subnets
  security_group_ids  = [aws_security_group.shared_vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-kms-vpce"
  })
}

resource "aws_vpc_endpoint" "logs" {
  count = var.provision_shared_services ? 1 : 0

  vpc_id              = local.selected_vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.shared_subnets
  security_group_ids  = [aws_security_group.shared_vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-logs-vpce"
  })
}

resource "aws_vpc_endpoint" "s3" {
  count = var.provision_shared_services ? 1 : 0

  vpc_id            = local.selected_vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = local.shared_route_table_ids

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-s3-vpce"
  })
}

resource "aws_ecs_task_definition" "proof_requestor" {
  count = var.provision_shared_services ? 1 : 0

  family                   = "${local.resource_name}-proof-requestor"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.shared_ecs_task_cpu)
  memory                   = tostring(var.shared_ecs_task_memory)
  execution_role_arn       = aws_iam_role.ecs_task_execution[0].arn
  task_role_arn            = aws_iam_role.proof_requestor_task[0].arn

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
          valueFrom = local.shared_sp1_requestor_secret_arn
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.proof_requestor[0].name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "proof-requestor"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = local.shared_proof_service_image != ""
      error_message = "shared_proof_service_image must be set when provision_shared_services=true."
    }
    precondition {
      condition     = local.shared_sp1_requestor_secret_arn != ""
      error_message = "shared_sp1_requestor_secret_arn must be set when provision_shared_services=true."
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
  count = var.provision_shared_services ? 1 : 0

  family                   = "${local.resource_name}-proof-funder"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.shared_ecs_task_cpu)
  memory                   = tostring(var.shared_ecs_task_memory)
  execution_role_arn       = aws_iam_role.ecs_task_execution[0].arn
  task_role_arn            = aws_iam_role.proof_funder_task[0].arn

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
          valueFrom = local.shared_sp1_funder_secret_arn
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.proof_funder[0].name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "proof-funder"
        }
      }
    }
  ])

  lifecycle {
    precondition {
      condition     = local.shared_proof_service_image != ""
      error_message = "shared_proof_service_image must be set when provision_shared_services=true."
    }
    precondition {
      condition     = local.shared_sp1_requestor_secret_arn != ""
      error_message = "shared_sp1_requestor_secret_arn must be set when provision_shared_services=true."
    }
    precondition {
      condition     = local.shared_sp1_funder_secret_arn != ""
      error_message = "shared_sp1_funder_secret_arn must be set when provision_shared_services=true."
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
  count = var.provision_shared_services ? 1 : 0

  name            = "${local.resource_name}-proof-requestor"
  cluster         = aws_ecs_cluster.shared[0].id
  task_definition = aws_ecs_task_definition.proof_requestor[0].arn
  desired_count   = var.shared_ecs_desired_count
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  network_configuration {
    subnets          = local.shared_subnets
    security_groups  = [aws_security_group.ecs[0].id]
    assign_public_ip = var.shared_ecs_assign_public_ip
  }

  depends_on = [aws_iam_role_policy_attachment.ecs_task_execution]

  tags = local.common_tags
}

resource "aws_ecs_service" "proof_funder" {
  count = var.provision_shared_services ? 1 : 0

  name            = "${local.resource_name}-proof-funder"
  cluster         = aws_ecs_cluster.shared[0].id
  task_definition = aws_ecs_task_definition.proof_funder[0].arn
  desired_count   = var.shared_ecs_desired_count
  launch_type     = "FARGATE"

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  network_configuration {
    subnets          = local.shared_subnets
    security_groups  = [aws_security_group.ecs[0].id]
    assign_public_ip = var.shared_ecs_assign_public_ip
  }

  depends_on = [aws_iam_role_policy_attachment.ecs_task_execution]

  tags = local.common_tags
}

resource "aws_lb" "ipfs" {
  count = var.provision_shared_services ? 1 : 0

  name               = local.ipfs_lb_name
  internal           = true
  load_balancer_type = "network"
  enable_cross_zone_load_balancing = true
  subnets            = local.shared_subnets

  lifecycle {
    precondition {
      condition     = length(local.shared_subnets) >= 2
      error_message = "IPFS NLB requires at least two subnets."
    }
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-ipfs"
  })
}

resource "aws_lb_target_group" "ipfs_api" {
  count = var.provision_shared_services ? 1 : 0

  name        = local.ipfs_target_group_name
  port        = var.shared_ipfs_api_port
  protocol    = "TCP"
  target_type = "instance"
  vpc_id      = local.selected_vpc_id

  health_check {
    protocol = "TCP"
    port     = tostring(var.shared_ipfs_api_port)
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-ipfs-api"
  })
}

resource "aws_lb_listener" "ipfs_api" {
  count = var.provision_shared_services ? 1 : 0

  load_balancer_arn = aws_lb.ipfs[0].arn
  port              = var.shared_ipfs_api_port
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ipfs_api[0].arn
  }
}

resource "aws_launch_template" "ipfs" {
  count = var.provision_shared_services ? 1 : 0

  name_prefix   = local.ipfs_launch_name_prefix
  image_id      = local.shared_ami_id
  instance_type = var.shared_instance_type
  key_name      = aws_key_pair.runner.key_name

  iam_instance_profile {
    name = local.instance_profile_name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ipfs[0].id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.shared_root_volume_size_gb
      volume_type           = "gp3"
      delete_on_termination = true
    }
  }

  block_device_mappings {
    device_name = "/dev/sdf"

    ebs {
      volume_size           = var.shared_ipfs_data_volume_size_gb
      volume_type           = "gp3"
      delete_on_termination = false
      encrypted             = true
    }
  }

  user_data = base64encode(<<-EOF
    #!/usr/bin/env bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y ca-certificates curl docker.io nginx unzip
    arch="$(uname -m)"
    case "$arch" in
      x86_64) awscli_arch="x86_64" ;;
      aarch64|arm64) awscli_arch="aarch64" ;;
      *) echo "unsupported AWS CLI architecture: $arch" >&2; exit 1 ;;
    esac
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$${awscli_arch}.zip" -o /tmp/awscliv2.zip
    rm -rf /tmp/aws
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
    rm -rf /tmp/aws /tmp/awscliv2.zip
    systemctl enable --now docker nginx

    ipfs_api_secret_arn="${aws_secretsmanager_secret.shared_ipfs_api_bearer_token[0].arn}"
    ipfs_api_bearer_token="$(AWS_PAGER="" aws --region ${var.aws_region} secretsmanager get-secret-value --secret-id "$ipfs_api_secret_arn" --query SecretString --output text)"
    imds_token="$(curl -fsS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')"
    private_ip="$(curl -fsS -H "X-aws-ec2-metadata-token: $imds_token" http://169.254.169.254/latest/meta-data/local-ipv4)"
    root_source="$(findmnt -n -o SOURCE /)"
    root_disk="/dev/$(lsblk -no PKNAME "$root_source")"
    data_disk="$(lsblk -dpno NAME,TYPE | awk '$2 == "disk" {print $1}' | grep -vx "$root_disk" | head -n1)"
    [[ -n "$data_disk" ]] || { echo "shared ipfs data disk not found" >&2; exit 1; }
    if ! blkid "$data_disk" >/dev/null 2>&1; then
      mkfs.ext4 -F "$data_disk"
    fi
    install -d -m 0755 /var/lib/intents-juno/ipfs
    data_uuid="$(blkid -s UUID -o value "$data_disk")"
    grep -q "$data_uuid /var/lib/intents-juno/ipfs " /etc/fstab || echo "UUID=$data_uuid /var/lib/intents-juno/ipfs ext4 defaults,nofail 0 2" >> /etc/fstab
    mountpoint -q /var/lib/intents-juno/ipfs || mount /var/lib/intents-juno/ipfs

    {
      printf 'server {\n'
      printf '  listen %s:%s;\n' "$private_ip" "${var.shared_ipfs_api_port}"
      printf '  location /api/v0/ {\n'
      printf '    if ($http_authorization != "Bearer %s") {\n' "$ipfs_api_bearer_token"
      printf '      return 401;\n'
      printf '    }\n'
      printf '    proxy_http_version 1.1;\n'
      printf '    proxy_buffering off;\n'
      printf '    proxy_request_buffering off;\n'
      printf '    proxy_set_header Host $host;\n'
      printf '    proxy_pass http://127.0.0.1:5001;\n'
      printf '  }\n'
      printf '  location / {\n'
      printf '    return 404;\n'
      printf '  }\n'
      printf '}\n'
    } >/etc/nginx/conf.d/intents-shared-ipfs.conf
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf
    nginx -t
    systemctl restart nginx

    docker rm -f intents-shared-ipfs >/dev/null 2>&1 || true
    docker pull ipfs/kubo:v0.32.1
    docker run -d \
      --name intents-shared-ipfs \
      --restart unless-stopped \
      --network host \
      -e IPFS_PATH=/data/ipfs \
      -v /var/lib/intents-juno/ipfs:/data/ipfs \
      ipfs/kubo:v0.32.1 daemon --migrate=true --api /ip4/127.0.0.1/tcp/5001 --routing=dhtclient
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
  count = var.provision_shared_services ? 1 : 0

  name                = "${local.resource_name}-ipfs"
  min_size            = var.shared_ipfs_min_size
  max_size            = var.shared_ipfs_max_size
  desired_capacity    = var.shared_ipfs_desired_capacity
  vpc_zone_identifier = local.shared_subnets
  target_group_arns   = [aws_lb_target_group.ipfs_api[0].arn]

  health_check_type         = "EC2"
  health_check_grace_period = 120

  launch_template {
    id      = aws_launch_template.ipfs[0].id
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
      condition     = var.shared_ipfs_desired_capacity >= var.shared_ipfs_min_size && var.shared_ipfs_desired_capacity <= var.shared_ipfs_max_size
      error_message = "shared_ipfs_desired_capacity must be between shared_ipfs_min_size and shared_ipfs_max_size."
    }
  }
}

resource "aws_security_group" "wireguard" {
  count = local.wireguard_enabled ? 1 : 0

  name        = "${local.resource_name}-wireguard-sg"
  description = "Security group for intents-juno live e2e backoffice WireGuard gateway"
  vpc_id      = local.selected_vpc_id

  ingress {
    description = "WireGuard ingress"
    from_port   = var.shared_wireguard_listen_port
    to_port     = var.shared_wireguard_listen_port
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-wireguard"
  })
}

data "aws_iam_policy_document" "wireguard_gateway_assume_role" {
  count = local.wireguard_enabled ? 1 : 0

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "wireguard_gateway" {
  count              = local.wireguard_enabled ? 1 : 0
  name               = "${local.resource_name}-wireguard-role"
  assume_role_policy = data.aws_iam_policy_document.wireguard_gateway_assume_role[0].json
  tags               = local.common_tags
}

resource "aws_secretsmanager_secret" "shared_wireguard_client_config" {
  count = local.wireguard_enabled ? 1 : 0
  name  = "${local.resource_name}-wireguard-client-config"
  tags  = local.common_tags
}

data "aws_iam_policy_document" "wireguard_gateway_access" {
  count = local.wireguard_enabled ? 1 : 0

  statement {
    sid = "AllowWireGuardClientConfigSecretWrite"
    actions = [
      "ec2:DescribeInstances",
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
      "secretsmanager:PutSecretValue",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "wireguard_gateway_access" {
  count  = local.wireguard_enabled ? 1 : 0
  name   = "${local.resource_name}-wireguard-access"
  role   = aws_iam_role.wireguard_gateway[0].id
  policy = data.aws_iam_policy_document.wireguard_gateway_access[0].json
}

resource "aws_iam_instance_profile" "wireguard_gateway" {
  count = local.wireguard_enabled ? 1 : 0
  name  = "${local.resource_name}-wireguard-profile"
  role  = aws_iam_role.wireguard_gateway[0].name
}

resource "aws_instance" "wireguard_gateway" {
  count                       = local.wireguard_enabled ? 1 : 0
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.shared_wireguard_instance_type
  subnet_id                   = local.wireguard_public_subnet_id
  vpc_security_group_ids      = [aws_security_group.wireguard[0].id]
  iam_instance_profile        = aws_iam_instance_profile.wireguard_gateway[0].name
  source_dest_check           = false
  associate_public_ip_address = false

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = true
  }

  user_data = <<-EOF
    #!/usr/bin/env bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y ca-certificates curl dnsmasq iptables unzip wireguard
    arch="$(uname -m)"
    case "$arch" in
      x86_64) awscli_arch="x86_64" ;;
      aarch64|arm64) awscli_arch="aarch64" ;;
      *) echo "unsupported AWS CLI architecture: $arch" >&2; exit 1 ;;
    esac
    curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-$${awscli_arch}.zip" -o /tmp/awscliv2.zip
    rm -rf /tmp/aws
    unzip -q /tmp/awscliv2.zip -d /tmp
    /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
    rm -rf /tmp/aws /tmp/awscliv2.zip

    imds_token="$(curl -fsS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')"
    instance_id="$(curl -fsS -H "X-aws-ec2-metadata-token: $imds_token" http://169.254.169.254/latest/meta-data/instance-id)"
    for _ in $(seq 1 30); do
      public_ip="$(AWS_PAGER="" aws --region ${var.aws_region} ec2 describe-instances --instance-ids "$instance_id" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null || true)"
      if [[ -n "$public_ip" && "$public_ip" != "None" ]]; then
        break
      fi
      sleep 2
    done
    [[ -n "$public_ip" && "$public_ip" != "None" ]] || { echo "wireguard public IP is unavailable" >&2; exit 1; }

    wireguard_client_config_secret_arn="${aws_secretsmanager_secret.shared_wireguard_client_config[0].arn}"
    wireguard_gateway_address_cidr="${local.wireguard_gateway_address_cidr}"
    wireguard_gateway_tunnel_ip="${local.wireguard_gateway_tunnel_ip}"
    wireguard_client_address_cidr="${local.wireguard_client_address_cidr}"
    wireguard_network_cidr="${var.shared_wireguard_network_cidr}"
    wireguard_listen_port="${var.shared_wireguard_listen_port}"
    wireguard_backoffice_private_endpoint="${local.wireguard_backoffice_private_endpoint}"
    wireguard_upstream_dns="169.254.169.253"
    default_iface="$(ip route show default | awk '/default/ {print $5; exit}')"

    install -d -m 0700 /etc/wireguard
    if [[ ! -f /etc/wireguard/server.key ]]; then
      umask 077
      wg genkey | tee /etc/wireguard/server.key | wg pubkey >/etc/wireguard/server.pub
      wg genkey | tee /etc/wireguard/client.key | wg pubkey >/etc/wireguard/client.pub
    fi

    server_private_key="$(cat /etc/wireguard/server.key)"
    server_public_key="$(cat /etc/wireguard/server.pub)"
    client_private_key="$(cat /etc/wireguard/client.key)"
    client_public_key="$(cat /etc/wireguard/client.pub)"

    cat >/etc/wireguard/wg0.conf <<WGEOF
    [Interface]
    Address = $${wireguard_gateway_address_cidr}
    ListenPort = $${wireguard_listen_port}
    PrivateKey = $${server_private_key}
    PostUp = iptables -t nat -A POSTROUTING -s $${wireguard_network_cidr} -o $${default_iface} -j MASQUERADE
    PostDown = iptables -t nat -D POSTROUTING -s $${wireguard_network_cidr} -o $${default_iface} -j MASQUERADE

    [Peer]
    PublicKey = $${client_public_key}
    AllowedIPs = $${wireguard_client_address_cidr}
    PersistentKeepalive = 25
    WGEOF

    cat >/etc/dnsmasq.d/intents-juno-wireguard.conf <<DNSEOF
    interface=wg0
    bind-interfaces
    listen-address=$${wireguard_gateway_tunnel_ip}
    address=/${var.shared_wireguard_backoffice_hostname}/$${wireguard_backoffice_private_endpoint}
    server=$${wireguard_upstream_dns}
    DNSEOF

    install -m 0644 /dev/null /etc/sysctl.d/99-intents-juno-wireguard.conf
    cat >/etc/sysctl.d/99-intents-juno-wireguard.conf <<SYSEOF
    net.ipv4.ip_forward=1
    SYSEOF
    sysctl --system >/dev/null

    systemctl enable dnsmasq
    systemctl restart dnsmasq
    systemctl enable wg-quick@wg0
    systemctl restart wg-quick@wg0

    client_config="$(cat <<CFGEOF
    [Interface]
    PrivateKey = $${client_private_key}
    Address = $${wireguard_client_address_cidr}
    DNS = $${wireguard_gateway_tunnel_ip}

    [Peer]
    PublicKey = $${server_public_key}
    Endpoint = $${public_ip}:$${wireguard_listen_port}
    AllowedIPs = $${wireguard_network_cidr}, $${wireguard_backoffice_private_endpoint}/32
    PersistentKeepalive = 25
    CFGEOF
    )"

    for _ in $(seq 1 10); do
      if AWS_PAGER="" aws --region ${var.aws_region} secretsmanager put-secret-value --secret-id "$wireguard_client_config_secret_arn" --secret-string "$client_config" >/dev/null; then
        break
      fi
      sleep 5
    done
  EOF

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-wireguard"
  })
}

resource "aws_eip" "wireguard_gateway" {
  count    = local.wireguard_enabled ? 1 : 0
  domain   = "vpc"
  instance = aws_instance.wireguard_gateway[0].id

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-wireguard"
  })
}

resource "aws_instance" "runner" {
  ami                    = local.runner_ami_id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.runner.key_name
  subnet_id              = local.selected_subnet_id
  vpc_security_group_ids = [aws_security_group.runner.id]
  iam_instance_profile   = local.instance_profile_name

  associate_public_ip_address = var.runner_associate_public_ip_address

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_size_gb
  }

  user_data = <<-EOF
    #!/usr/bin/env bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y ca-certificates curl git jq unzip rsync age
  EOF

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-runner"
  })
}

resource "aws_launch_template" "operator" {
  count = var.operator_instance_count

  name_prefix   = "${local.resource_name}-operator-${count.index + 1}-"
  image_id      = local.operator_ami_id
  instance_type = var.operator_instance_type
  key_name      = aws_key_pair.runner.key_name

  iam_instance_profile {
    name = local.instance_profile_name
  }

  network_interfaces {
    associate_public_ip_address = var.operator_associate_public_ip_address
    delete_on_termination       = true
    security_groups             = [aws_security_group.operator.id]
  }

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_type           = "gp3"
      volume_size           = var.operator_root_volume_size_gb
      delete_on_termination = true
      encrypted             = true
    }
  }

  user_data = base64encode(<<-EOF
    #!/usr/bin/env bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y ca-certificates curl git jq unzip rsync age
  EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${local.resource_name}-operator-${count.index + 1}"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      Name = "${local.resource_name}-operator-${count.index + 1}"
    })
  }
}

resource "aws_autoscaling_group" "operator" {
  count = var.operator_instance_count

  name                = "${local.resource_name}-operator-${count.index + 1}"
  min_size            = 1
  max_size            = 1
  desired_capacity    = 1
  vpc_zone_identifier = var.subnet_id != "" ? [var.subnet_id] : local.public_one_per_az

  health_check_type         = "EC2"
  health_check_grace_period = 120

  launch_template {
    id      = aws_launch_template.operator[count.index].id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${local.resource_name}-operator-${count.index + 1}"
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
}

data "aws_instances" "operator" {
  count = var.operator_instance_count

  instance_state_names = ["pending", "running", "stopped", "stopping"]

  filter {
    name   = "tag:aws:autoscaling:groupName"
    values = [aws_autoscaling_group.operator[count.index].name]
  }

  depends_on = [aws_autoscaling_group.operator]
}

data "aws_instance" "operator" {
  count = var.operator_instance_count

  instance_id = one(data.aws_instances.operator[count.index].ids)

  depends_on = [data.aws_instances.operator]
}
