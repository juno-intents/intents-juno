provider "aws" {
  region = var.aws_region
}

provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

locals {
  resource_slug = trim(replace(lower("juno-app-edge-${var.deployment_id}"), "_", "-"), "-")
  common_tags = {
    Project    = "intents-juno"
    ManagedBy  = "terraform"
    Stack      = "app-edge"
    Deployment = var.deployment_id
  }
  origin_is_ipv4                       = can(regex("^([0-9]{1,3}\\.){3}[0-9]{1,3}$", trimspace(var.origin_endpoint)))
  cloudfront_cache_policy_id           = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
  cloudfront_origin_request_policy_id  = "b689b0a8-53d0-40ab-baf2-68738e2966ac"
}

data "aws_ec2_managed_prefix_list" "cloudfront_origin" {
  count = var.security_group_id != "" ? 1 : 0
  name  = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_route53_record" "origin_a" {
  count   = local.origin_is_ipv4 ? 1 : 0
  zone_id = var.zone_id
  name    = var.origin_record_name
  type    = "A"
  ttl     = 60
  records = [var.origin_endpoint]
}

resource "aws_route53_record" "origin_cname" {
  count   = local.origin_is_ipv4 ? 0 : 1
  zone_id = var.zone_id
  name    = var.origin_record_name
  type    = "CNAME"
  ttl     = 60
  records = [var.origin_endpoint]
}

resource "aws_acm_certificate" "viewer" {
  provider                  = aws.us_east_1
  domain_name               = var.bridge_record_name
  subject_alternative_names = [var.backoffice_record_name]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_slug}-viewer-cert"
  })
}

resource "aws_route53_record" "viewer_validation" {
  for_each = {
    for dvo in aws_acm_certificate.viewer.domain_validation_options :
    dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  zone_id = var.zone_id
  name    = each.value.name
  type    = each.value.type
  ttl     = 60
  records = [each.value.record]
}

resource "aws_acm_certificate_validation" "viewer" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.viewer.arn
  validation_record_fqdns = [for record in aws_route53_record.viewer_validation : record.fqdn]
}

resource "aws_wafv2_web_acl" "app" {
  provider = aws.us_east_1
  name     = "${local.resource_slug}-waf"
  scope    = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "rate-limit"
    priority = 0

    action {
      block {}
    }

    statement {
      rate_based_statement {
        aggregate_key_type = "IP"
        limit              = var.rate_limit
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "rate-limit"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-common"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-common"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-ip-reputation"
    priority = 11

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAmazonIpReputationList"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-ip-reputation"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "aws-known-bad-inputs"
    priority = 12

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "aws-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${replace(local.resource_slug, "-", "_")}_waf"
    sampled_requests_enabled   = true
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_slug}-waf"
  })
}

resource "aws_cloudfront_distribution" "bridge" {
  provider            = aws.us_east_1
  enabled             = true
  is_ipv6_enabled     = true
  wait_for_deployment = true
  aliases             = [var.bridge_record_name]
  web_acl_id          = aws_wafv2_web_acl.app.arn

  origin {
    domain_name = var.origin_record_name
    origin_id   = "app-origin"
    origin_path = "/bridge"

    custom_origin_config {
      http_port              = var.origin_http_port
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "app-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    compress               = true
    cache_policy_id        = local.cloudfront_cache_policy_id
    origin_request_policy_id = local.cloudfront_origin_request_policy_id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.viewer.certificate_arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_slug}-bridge"
  })
}

resource "aws_cloudfront_distribution" "backoffice" {
  provider            = aws.us_east_1
  enabled             = true
  is_ipv6_enabled     = true
  wait_for_deployment = true
  aliases             = [var.backoffice_record_name]
  web_acl_id          = aws_wafv2_web_acl.app.arn

  origin {
    domain_name = var.origin_record_name
    origin_id   = "app-origin"
    origin_path = "/ops"

    custom_origin_config {
      http_port              = var.origin_http_port
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "app-origin"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD", "OPTIONS"]
    compress               = true
    cache_policy_id        = local.cloudfront_cache_policy_id
    origin_request_policy_id = local.cloudfront_origin_request_policy_id
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.viewer.certificate_arn
    minimum_protocol_version = "TLSv1.2_2021"
    ssl_support_method       = "sni-only"
  }

  tags = merge(local.common_tags, {
    Name = "${local.resource_slug}-backoffice"
  })
}

resource "aws_route53_record" "bridge_alias_a" {
  zone_id         = var.zone_id
  name            = var.bridge_record_name
  type            = "A"
  allow_overwrite = true

  alias {
    name                   = aws_cloudfront_distribution.bridge.domain_name
    zone_id                = aws_cloudfront_distribution.bridge.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "bridge_alias_aaaa" {
  zone_id         = var.zone_id
  name            = var.bridge_record_name
  type            = "AAAA"
  allow_overwrite = true

  alias {
    name                   = aws_cloudfront_distribution.bridge.domain_name
    zone_id                = aws_cloudfront_distribution.bridge.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "backoffice_alias_a" {
  zone_id         = var.zone_id
  name            = var.backoffice_record_name
  type            = "A"
  allow_overwrite = true

  alias {
    name                   = aws_cloudfront_distribution.backoffice.domain_name
    zone_id                = aws_cloudfront_distribution.backoffice.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "backoffice_alias_aaaa" {
  zone_id         = var.zone_id
  name            = var.backoffice_record_name
  type            = "AAAA"
  allow_overwrite = true

  alias {
    name                   = aws_cloudfront_distribution.backoffice.domain_name
    zone_id                = aws_cloudfront_distribution.backoffice.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_security_group_rule" "origin_http_from_cloudfront" {
  count             = var.security_group_id != "" ? 1 : 0
  type              = "ingress"
  description       = "CloudFront origin HTTP"
  from_port         = var.origin_http_port
  to_port           = var.origin_http_port
  protocol          = "tcp"
  security_group_id = var.security_group_id
  prefix_list_ids   = [data.aws_ec2_managed_prefix_list.cloudfront_origin[0].id]
}

resource "aws_cloudwatch_metric_alarm" "bridge_5xx" {
  provider            = aws.us_east_1
  alarm_name          = "${local.resource_slug}-bridge-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "5xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = 300
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Bridge CloudFront 5xx error rate is elevated."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    DistributionId = aws_cloudfront_distribution.bridge.id
    Region         = "Global"
  }
}

resource "aws_cloudwatch_metric_alarm" "backoffice_5xx" {
  provider            = aws.us_east_1
  alarm_name          = "${local.resource_slug}-backoffice-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "5xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = 300
  statistic           = "Average"
  threshold           = 1
  alarm_description   = "Backoffice CloudFront 5xx error rate is elevated."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    DistributionId = aws_cloudfront_distribution.backoffice.id
    Region         = "Global"
  }
}

resource "aws_cloudwatch_metric_alarm" "waf_blocked_requests" {
  provider            = aws.us_east_1
  alarm_name          = "${local.resource_slug}-waf-blocked"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = 1000
  alarm_description   = "WAF is blocking a large burst of requests."
  alarm_actions       = var.alarm_actions
  ok_actions          = var.alarm_actions

  dimensions = {
    WebACL = aws_wafv2_web_acl.app.name
    Region = "CloudFront"
    Rule   = "ALL"
  }
}

resource "aws_shield_protection" "bridge" {
  provider     = aws.us_east_1
  count        = var.enable_shield_advanced ? 1 : 0
  name         = "${local.resource_slug}-bridge-shield"
  resource_arn = aws_cloudfront_distribution.bridge.arn
}

resource "aws_shield_protection" "backoffice" {
  provider     = aws.us_east_1
  count        = var.enable_shield_advanced ? 1 : 0
  name         = "${local.resource_slug}-backoffice-shield"
  resource_arn = aws_cloudfront_distribution.backoffice.arn
}
