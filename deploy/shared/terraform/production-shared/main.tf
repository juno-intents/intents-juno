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

  aurora_final_snapshot_identifier = trimspace(var.shared_postgres_final_snapshot_identifier) != "" ? trimspace(var.shared_postgres_final_snapshot_identifier) : "${local.resource_slug}-shared-aurora-final"
  shared_proof_service_image       = trimspace(var.shared_proof_service_image) != "" ? trimspace(var.shared_proof_service_image) : "${aws_ecr_repository.proof_services.repository_url}:latest"

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

resource "aws_iam_role_policy_attachment" "proof_requestor_execution" {
  role       = aws_iam_role.proof_requestor_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy_attachment" "proof_funder_execution" {
  role       = aws_iam_role.proof_funder_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "proof_requestor_secret_access" {
  statement {
    sid = "AllowProofRequestorSecretRead"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
    ]
    resources = [var.shared_sp1_requestor_secret_arn]
  }
}

data "aws_iam_policy_document" "proof_funder_secret_access" {
  statement {
    sid = "AllowProofFunderSecretRead"
    actions = [
      "secretsmanager:DescribeSecret",
      "secretsmanager:GetSecretValue",
    ]
    resources = [var.shared_sp1_funder_secret_arn]
  }
}

resource "aws_iam_role_policy" "proof_requestor_secret_access" {
  name   = "${local.resource_name}-proof-requestor-secrets"
  role   = aws_iam_role.proof_requestor_execution.id
  policy = data.aws_iam_policy_document.proof_requestor_secret_access.json
}

resource "aws_iam_role_policy" "proof_funder_secret_access" {
  name   = "${local.resource_name}-proof-funder-secrets"
  role   = aws_iam_role.proof_funder_execution.id
  policy = data.aws_iam_policy_document.proof_funder_secret_access.json
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

  depends_on = [aws_iam_role_policy_attachment.proof_requestor_execution]
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

  depends_on = [aws_iam_role_policy_attachment.proof_funder_execution]
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

  health_check_type         = "EC2"
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
