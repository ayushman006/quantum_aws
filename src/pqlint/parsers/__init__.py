"""IaC parsers for Terraform and CloudFormation."""

from pqlint.parsers.terraform import parse_terraform_directory, parse_terraform_file

__all__ = ["parse_terraform_directory", "parse_terraform_file"]
