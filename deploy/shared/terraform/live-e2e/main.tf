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
