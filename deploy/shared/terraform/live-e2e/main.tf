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

data "aws_subnets" "public" {
  filter {
    name   = "map-public-ip-on-launch"
    values = ["true"]
  }

  dynamic "filter" {
    for_each = var.vpc_id == "" ? [] : [var.vpc_id]
    content {
      name   = "vpc-id"
      values = [filter.value]
    }
  }
}

locals {
  selected_subnet_id = var.subnet_id != "" ? var.subnet_id : data.aws_subnets.public.ids[0]
}

data "aws_subnet" "selected" {
  id = local.selected_subnet_id
}

locals {
  selected_vpc_id = var.vpc_id != "" ? var.vpc_id : data.aws_subnet.selected.vpc_id
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

resource "aws_security_group" "shared" {
  count = var.provision_shared_services ? 1 : 0

  name        = "${local.resource_name}-shared-sg"
  description = "Security group for intents-juno live e2e shared services"
  vpc_id      = local.selected_vpc_id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_ssh_cidr]
  }

  ingress {
    description     = "Postgres from runner"
    from_port       = var.shared_postgres_port
    to_port         = var.shared_postgres_port
    protocol        = "tcp"
    security_groups = [aws_security_group.runner.id]
  }

  ingress {
    description     = "Kafka from runner"
    from_port       = var.shared_kafka_port
    to_port         = var.shared_kafka_port
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

resource "aws_instance" "runner" {
  ami                    = local.runner_ami_id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.runner.key_name
  subnet_id              = local.selected_subnet_id
  vpc_security_group_ids = [aws_security_group.runner.id]
  iam_instance_profile   = local.instance_profile_name

  associate_public_ip_address = true

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

resource "aws_instance" "shared" {
  count = var.provision_shared_services ? 1 : 0

  ami                    = local.shared_ami_id
  instance_type          = var.shared_instance_type
  key_name               = aws_key_pair.runner.key_name
  subnet_id              = local.selected_subnet_id
  vpc_security_group_ids = [aws_security_group.shared[0].id]
  iam_instance_profile   = local.instance_profile_name

  associate_public_ip_address = true

  root_block_device {
    volume_type = "gp3"
    volume_size = var.shared_root_volume_size_gb
  }

  user_data = <<-EOF
    #!/usr/bin/env bash
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y ca-certificates curl docker.io
    systemctl enable --now docker

    private_ip="$$(hostname -I | awk '{print $$1}')"

    docker rm -f intents-shared-postgres intents-shared-kafka >/dev/null 2>&1 || true

    docker run -d \
      --name intents-shared-postgres \
      --restart unless-stopped \
      -e POSTGRES_USER='${var.shared_postgres_user}' \
      -e POSTGRES_PASSWORD='${var.shared_postgres_password}' \
      -e POSTGRES_DB='${var.shared_postgres_db}' \
      -p ${var.shared_postgres_port}:5432 \
      postgres:16-alpine

    docker run -d \
      --name intents-shared-kafka \
      --restart unless-stopped \
      -p ${var.shared_kafka_port}:9092 \
      docker.redpanda.com/redpandadata/redpanda:v24.3.7 \
      redpanda start \
        --overprovisioned \
        --smp 1 \
        --memory 1G \
        --reserve-memory 0M \
        --node-id 0 \
        --check=false \
        --kafka-addr PLAINTEXT://0.0.0.0:9092 \
        --advertise-kafka-addr PLAINTEXT://$${private_ip}:${var.shared_kafka_port}
  EOF

  tags = merge(local.common_tags, {
    Name = "${local.resource_name}-shared"
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

  associate_public_ip_address = true

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
