provider "aws" {
  region = var.aws_region
}

locals {
  resource_slug = trim(replace(lower("juno-app-runtime-${var.deployment_id}"), "_", "-"), "-")
  common_tags = merge({
    Project    = "intents-juno"
    ManagedBy  = "terraform"
    Stack      = "app-runtime"
    Deployment = var.deployment_id
  }, var.tags)
}

resource "aws_security_group" "public_bridge_lb" {
  name        = substr("${local.resource_slug}-bridge-lb", 0, 32)
  description = "Public bridge application load balancer"
  vpc_id      = var.vpc_id

  ingress {
    description      = "HTTPS from the internet"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    description = "Allow load balancer egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = substr("${local.resource_slug}-bridge-lb", 0, 32)
  })
}

resource "aws_security_group" "internal_backoffice_lb" {
  name        = substr("${local.resource_slug}-backoffice-lb", 0, 32)
  description = "Internal backoffice application load balancer"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from WireGuard gateways"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.wireguard_cidr_blocks
  }

  egress {
    description = "Allow load balancer egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = substr("${local.resource_slug}-backoffice-lb", 0, 32)
  })
}

resource "aws_security_group" "app" {
  name        = substr("${local.resource_slug}-app", 0, 32)
  description = "App instances behind the bridge and backoffice load balancers"
  vpc_id      = var.vpc_id

  ingress {
    description     = "HTTPS from public bridge load balancer"
    from_port       = var.app_https_port
    to_port         = var.app_https_port
    protocol        = "tcp"
    security_groups = [aws_security_group.public_bridge_lb.id]
  }

  ingress {
    description     = "HTTPS from internal backoffice load balancer"
    from_port       = var.app_https_port
    to_port         = var.app_https_port
    protocol        = "tcp"
    security_groups = [aws_security_group.internal_backoffice_lb.id]
  }

  egress {
    description = "Allow app egress"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = substr("${local.resource_slug}-app", 0, 32)
  })
}

resource "aws_lb" "public_bridge" {
  name                             = substr("${local.resource_slug}-bridge", 0, 32)
  internal                         = false
  load_balancer_type               = "application"
  security_groups                  = [aws_security_group.public_bridge_lb.id]
  subnets                          = var.public_subnet_ids
  enable_cross_zone_load_balancing = true
  drop_invalid_header_fields       = true
  idle_timeout                     = 60

  tags = merge(local.common_tags, {
    Name = substr("${local.resource_slug}-bridge", 0, 32)
  })
}

resource "aws_lb" "internal_backoffice" {
  name                             = substr("${local.resource_slug}-backoffice", 0, 32)
  internal                         = true
  load_balancer_type               = "application"
  security_groups                  = [aws_security_group.internal_backoffice_lb.id]
  subnets                          = var.private_subnet_ids
  enable_cross_zone_load_balancing = true
  drop_invalid_header_fields       = true
  idle_timeout                     = 60

  tags = merge(local.common_tags, {
    Name = substr("${local.resource_slug}-backoffice", 0, 32)
  })
}

resource "aws_lb_target_group" "bridge" {
  name        = substr("${local.resource_slug}-bridge-tg", 0, 32)
  port        = var.app_https_port
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    protocol            = "HTTPS"
    path                = var.bridge_health_check_path
    port                = "traffic-port"
    matcher             = "200-399"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    timeout             = 5
  }

  tags = merge(local.common_tags, {
    Name = substr("${local.resource_slug}-bridge-tg", 0, 32)
  })
}

resource "aws_lb_target_group" "backoffice" {
  name        = substr("${local.resource_slug}-backoffice-tg", 0, 32)
  port        = var.app_https_port
  protocol    = "HTTPS"
  target_type = "instance"
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    protocol            = "HTTPS"
    path                = var.backoffice_health_check_path
    port                = "traffic-port"
    matcher             = "200-399"
    healthy_threshold   = 2
    unhealthy_threshold = 2
    interval            = 30
    timeout             = 5
  }

  tags = merge(local.common_tags, {
    Name = substr("${local.resource_slug}-backoffice-tg", 0, 32)
  })
}

resource "aws_lb_listener" "public_bridge_https" {
  load_balancer_arn = aws_lb.public_bridge.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.public_bridge_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.bridge.arn
  }
}

resource "aws_lb_listener" "internal_backoffice_https" {
  load_balancer_arn = aws_lb.internal_backoffice.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.internal_backoffice_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.backoffice.arn
  }
}

resource "aws_launch_template" "app" {
  name_prefix            = "${local.resource_slug}-"
  update_default_version = true
  image_id               = var.app_ami_id
  instance_type          = var.app_instance_type
  user_data              = base64encode(var.user_data)

  iam_instance_profile {
    name = var.app_instance_profile_name
  }

  vpc_security_group_ids = [aws_security_group.app.id]

  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = var.root_volume_size_gb
      volume_type           = "gp3"
      encrypted             = true
      delete_on_termination = true
    }
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${local.resource_slug}-app"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = local.common_tags
  }
}

resource "aws_autoscaling_group" "app" {
  name                      = "${local.resource_slug}-asg"
  desired_capacity          = var.app_desired_capacity
  min_size                  = var.app_min_size
  max_size                  = var.app_max_size
  health_check_type         = "ELB"
  health_check_grace_period = 300
  vpc_zone_identifier       = var.private_subnet_ids
  target_group_arns         = [aws_lb_target_group.bridge.arn, aws_lb_target_group.backoffice.arn]

  launch_template {
    id      = aws_launch_template.app.id
    version = aws_launch_template.app.latest_version
  }

  instance_refresh {
    strategy = "Rolling"
    triggers = ["launch_template"]

    preferences {
      min_healthy_percentage = 50
      instance_warmup        = 120
    }
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

resource "aws_cloudwatch_metric_alarm" "app_in_service" {
  alarm_name          = "${local.resource_slug}-in-service"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "GroupInServiceInstances"
  namespace           = "AWS/AutoScaling"
  period              = 60
  statistic           = "Minimum"
  threshold           = var.app_min_size
  alarm_description   = "App autoscaling group is below the minimum healthy instance count."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app.name
  }
}

resource "aws_cloudwatch_metric_alarm" "public_bridge_5xx" {
  alarm_name          = "${local.resource_slug}-bridge-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_ELB_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Public bridge load balancer is returning 5xx responses."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    LoadBalancer = aws_lb.public_bridge.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "internal_backoffice_unhealthy_hosts" {
  alarm_name          = "${local.resource_slug}-backoffice-unhealthy"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 1
  alarm_description   = "Internal backoffice load balancer has unhealthy app targets."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    LoadBalancer = aws_lb.internal_backoffice.arn_suffix
    TargetGroup  = aws_lb_target_group.backoffice.arn_suffix
  }
}
