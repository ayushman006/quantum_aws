"""Baseline AWS provider defaults for missing IaC attributes.

Models default values applied by AWS or the AWS Terraform provider when
configuration attributes are omitted.
"""

from typing import Any, Dict


def apply_provider_defaults(resource_type: str, attributes: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply AWS provider default values for attributes omitted in Terraform configurations.
    Returns a copy of attributes with defaults populated for unconfigured keys.
    """
    attrs = dict(attributes)

    if resource_type == "aws_kms_key":
        # AWS KMS defaults to SYMMETRIC_DEFAULT when customer_master_key_spec is omitted
        if "customer_master_key_spec" not in attrs and "key_spec" not in attrs:
            attrs["customer_master_key_spec"] = "SYMMETRIC_DEFAULT"

    elif resource_type == "aws_acm_certificate":
        # AWS ACM defaults to RSA_2048 when key_algorithm is omitted
        if "key_algorithm" not in attrs:
            attrs["key_algorithm"] = "RSA_2048"

    elif resource_type == "aws_lb_listener":
        # AWS ALB/NLB HTTPS and TLS listeners default to ELBSecurityPolicy-2016-08 if omitted
        raw_proto = str(attrs.get("protocol", "")).upper()
        if raw_proto in ("HTTPS", "TLS"):
            if "ssl_policy" not in attrs or not attrs.get("ssl_policy"):
                attrs["ssl_policy"] = "ELBSecurityPolicy-2016-08"

    elif resource_type == "aws_s3_bucket_server_side_encryption_configuration":
        # S3 defaults to AES256 server-side encryption if no rule is supplied
        if "rule" not in attrs or not attrs.get("rule"):
            attrs["rule"] = [
                {"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}
            ]

    elif resource_type == "aws_cloudfront_distribution":
        if "viewer_certificate" not in attrs or not attrs.get("viewer_certificate"):
            attrs["viewer_certificate"] = {"minimum_protocol_version": "TLSv1"}

    return attrs
