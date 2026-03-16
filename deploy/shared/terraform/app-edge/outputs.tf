output "bridge_distribution_id" {
  value = aws_cloudfront_distribution.bridge.id
}

output "bridge_distribution_domain_name" {
  value = aws_cloudfront_distribution.bridge.domain_name
}

output "backoffice_distribution_id" {
  value = aws_cloudfront_distribution.backoffice.id
}

output "backoffice_distribution_domain_name" {
  value = aws_cloudfront_distribution.backoffice.domain_name
}

output "origin_record_name" {
  value = var.origin_record_name
}
