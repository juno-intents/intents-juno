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

resource "aws_instance" "runner" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = aws_key_pair.runner.key_name
  subnet_id              = local.selected_subnet_id
  vpc_security_group_ids = [aws_security_group.runner.id]
  iam_instance_profile   = var.iam_instance_profile == "" ? null : var.iam_instance_profile

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

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.shared_instance_type
  key_name               = aws_key_pair.runner.key_name
  subnet_id              = local.selected_subnet_id
  vpc_security_group_ids = [aws_security_group.shared[0].id]
  iam_instance_profile   = var.iam_instance_profile == "" ? null : var.iam_instance_profile

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
