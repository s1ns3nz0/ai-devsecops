output "dashboard_url" {
  value = "https://${local.domain}"
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.dashboard.id
}

output "s3_bucket_name" {
  value = aws_s3_bucket.dashboard.id
}

output "github_actions_role_arn" {
  value = aws_iam_role.github_actions.arn
}
