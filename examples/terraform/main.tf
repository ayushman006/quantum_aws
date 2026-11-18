resource "aws_kms_key" "quantum_vulnerable_key" {
  description              = "KMS key using quantum-vulnerable RSA"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "SIGN_VERIFY"
}

resource "aws_acm_certificate" "quantum_vulnerable_cert" {
  domain_name   = "api.example.com"
  key_algorithm = "RSA_2048"
}

resource "aws_lb_listener" "legacy_alb_listener" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/123"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "standard_s3_encryption" {
  bucket = "sensitive-data-bucket"

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
