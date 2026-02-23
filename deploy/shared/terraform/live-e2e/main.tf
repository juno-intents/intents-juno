provider "aws" {
  region = var.aws_region
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
  selected_subnet_id = var.subnet_id != "" ? var.subnet_id : data.aws_subnets.selected_vpc.ids[0]
}

data "aws_subnet" "selected" {
  id = local.selected_subnet_id
}

locals {
  selected_vpc_id = var.vpc_id != "" ? var.vpc_id : data.aws_subnet.selected.vpc_id
}

data "aws_subnets" "shared_vpc" {
  filter {
    name   = "vpc-id"
    values = [local.selected_vpc_id]
  }
}

locals {
  vpc_subnets    = sort(data.aws_subnets.shared_vpc.ids)
  shared_subnets = length(var.shared_subnet_ids) > 0 ? sort(var.shared_subnet_ids) : (length(local.vpc_subnets) >= 2 ? slice(local.vpc_subnets, 0, 2) : local.vpc_subnets)
}

data "aws_subnet" "shared" {
  for_each = var.provision_shared_services ? toset(local.shared_subnets) : toset([])
  id       = each.value
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

  resource_slug           = trim(replace(lower(local.resource_name), "_", "-"), "-")
  ipfs_lb_name            = trim(substr("${local.resource_slug}-ipfs", 0, 32), "-")
  ipfs_target_group_name  = trim(substr("${local.resource_slug}-ipfstg", 0, 32), "-")
  ipfs_launch_name_prefix = trim(substr("${local.resource_slug}-ipfs-", 0, 32), "-")
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

data "aws_iam_policy_document" "live_e2e_inline" {
  statement {
    sid    = "AllowDKGBucketList"
    effect = "Allow"
    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket"
    ]
    resources = [
      aws_s3_bucket.dkg_keypackages.arn
    ]
  }

  statement {
    sid    = "AllowDKGBucketObjects"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:AbortMultipartUpload",
      "s3:ListBucketMultipartUploads",
      "s3:ListMultipartUploadParts"
    ]
    resources = [
      "${aws_s3_bucket.dkg_keypackages.arn}/*"
    ]
  }

  statement {
    sid    = "AllowDKGKMS"
    effect = "Allow"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = [
      aws_kms_key.dkg.arn
    ]
  }

  dynamic "statement" {
    for_each = var.provision_shared_services ? [1] : []
    content {
      sid    = "AllowSharedECSServiceRollout"
      effect = "Allow"
      actions = [
        "ecs:DescribeClusters",
        "ecs:DescribeServices",
        "ecs:DescribeTaskDefinition",
        "ecs:RegisterTaskDefinition",
        "ecs:UpdateService"
      ]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.provision_shared_services ? [1] : []
    content {
      sid    = "AllowPassSharedECSTaskExecutionRole"
      effect = "Allow"
      actions = [
        "iam:PassRole"
      ]
      resources = [
        aws_iam_role.ecs_task_execution[0].arn
      ]

      condition {
        test     = "StringEquals"
        variable = "iam:PassedToService"
        values   = ["ecs-tasks.amazonaws.com"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.provision_shared_services ? [1] : []
    content {
      sid    = "AllowSharedECSLogTail"
      effect = "Allow"
      actions = [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:FilterLogEvents",
        "logs:GetLogEvents"
      ]
      resources = ["*"]
    }
  }
}

resource "aws_iam_role_policy" "live_e2e_inline" {
  count = local.managed_instance_profile_enabled ? 1 : 0

  name   = "${local.resource_name}-instance-inline"
  role   = aws_iam_role.live_e2e[0].id
  policy = data.aws_iam_policy_document.live_e2e_inline.json
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

resource "aws_msk_cluster" "shared" {
  count = var.provision_shared_services ? 1 : 0

  cluster_name           = "${local.resource_name}-shared-msk"
  kafka_version          = var.shared_msk_kafka_version
  number_of_broker_nodes = length(local.shared_subnets)

  broker_node_group_info {
    instance_type   = var.shared_msk_broker_instance_type
    client_subnets  = local.shared_subnets
    security_groups = [aws_security_group.shared[0].id]

    storage_info {
      ebs_storage_info {
        volume_size = var.shared_msk_broker_ebs_volume_size_gb
      }
    }
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
  shared_proof_service_image            = trimspace(var.shared_proof_service_image) != "" ? trimspace(var.shared_proof_service_image) : try("${aws_ecr_repository.proof_services[0].repository_url}:latest", "")
  shared_boundless_requestor_secret_arn = trimspace(var.shared_boundless_requestor_secret_arn)
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

resource "aws_ecs_task_definition" "proof_requestor" {
  count = var.provision_shared_services ? 1 : 0

  family                   = "${local.resource_name}-proof-requestor"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = tostring(var.shared_ecs_task_cpu)
  memory                   = tostring(var.shared_ecs_task_memory)
  execution_role_arn       = aws_iam_role.ecs_task_execution[0].arn

  container_definitions = jsonencode([
    {
      name      = "proof-requestor"
      image     = local.shared_proof_service_image
      essential = true
      command   = ["/usr/local/bin/proof-requestor"]
      environment = [
        {
          name  = "JUNO_QUEUE_KAFKA_TLS"
          value = "true"
        }
      ]
      secrets = [
        {
          name      = "PROOF_REQUESTOR_KEY"
          valueFrom = local.shared_boundless_requestor_secret_arn
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
      error_message = "shared proof service image must not be empty."
    }
    precondition {
      condition     = local.shared_boundless_requestor_secret_arn != ""
      error_message = "shared_boundless_requestor_secret_arn must be set when provision_shared_services=true."
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

  container_definitions = jsonencode([
    {
      name      = "proof-funder"
      image     = local.shared_proof_service_image
      essential = true
      command   = ["/usr/local/bin/proof-funder"]
      environment = [
        {
          name  = "JUNO_QUEUE_KAFKA_TLS"
          value = "true"
        }
      ]
      secrets = [
        {
          name      = "PROOF_FUNDER_KEY"
          valueFrom = local.shared_boundless_requestor_secret_arn
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
      error_message = "shared proof service image must not be empty."
    }
    precondition {
      condition     = local.shared_boundless_requestor_secret_arn != ""
      error_message = "shared_boundless_requestor_secret_arn must be set when provision_shared_services=true."
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

  vpc_security_group_ids = [aws_security_group.ipfs[0].id]

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.shared_root_volume_size_gb
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
    docker pull ipfs/kubo:v0.32.1
    docker run -d \
      --name intents-shared-ipfs \
      --restart unless-stopped \
      -p ${var.shared_ipfs_api_port}:5001 \
      ipfs/kubo:v0.32.1 daemon --migrate=true --api /ip4/0.0.0.0/tcp/5001 --routing=dhtclient
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

resource "aws_instance" "operator" {
  count = var.operator_instance_count

  ami                    = local.operator_ami_id
  instance_type          = var.operator_instance_type
  key_name               = aws_key_pair.runner.key_name
  subnet_id              = local.selected_subnet_id
  vpc_security_group_ids = [aws_security_group.operator.id]
  iam_instance_profile   = local.instance_profile_name

  associate_public_ip_address = var.operator_associate_public_ip_address

  root_block_device {
    volume_type = "gp3"
    volume_size = var.operator_root_volume_size_gb
  }

  user_data = <<-EOF
    #!/usr/bin/env bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y ca-certificates curl git jq unzip rsync age
  EOF

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-operator-${count.index + 1}"
  })
}
