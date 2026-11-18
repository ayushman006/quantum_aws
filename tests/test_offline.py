"""Offline execution verification tests for pqlint (FR-08).

Guarantees that IaC scanning makes zero network calls and executes entirely
offline by blocking socket instantiation and verifying forbidden imports.
"""

import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pqlint.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """Globally block network access by monkeypatching socket.socket."""

    def forbidden_socket(*args, **kwargs):
        raise RuntimeError("Network calls strictly forbidden")

    monkeypatch.setattr(socket, "socket", forbidden_socket)


def test_scan_iac_runs_offline_with_blocked_sockets(tmp_path: Path):
    """Verify that scan-iac executes fully offline without invoking socket operations."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
        resource "aws_kms_key" "offline_test" {
          customer_master_key_spec = "RSA_2048"
        }
        """,
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan-iac", str(tmp_path)])

    # Must complete successfully and detect finding without tripping the socket block
    assert result.exit_code in (0, 1)
    assert "Scanning local Terraform directory" in result.stdout
    assert "Parsed 1 resources" in result.stdout
    assert "PQL-KMS-001" in result.stdout


def test_scan_iac_dynamic_block_offline(tmp_path: Path):
    """Verify that dynamic blocks are parsed and evaluated offline."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
        resource "aws_s3_bucket_server_side_encryption_configuration" "dyn_bucket" {
          bucket = "offline-bucket"

          dynamic "rule" {
            for_each = [1]
            content {
              apply_server_side_encryption_by_default {
                sse_algorithm = "AES256"
              }
            }
          }
        }
        """,
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan-iac", str(tmp_path), "--fail-on", "info"])
    assert result.exit_code == 1
    assert "PQL-S3-001" in result.stdout


def test_import_ban_offline_guarantee():
    """Verify that no prohibited network or subprocess modules are imported in production code."""
    import ast

    forbidden = {
        "socket",
        "subprocess",
        "requests",
        "httpx",
        "ftplib",
        "smtplib",
    }

    src_dir = Path(__file__).resolve().parent.parent / "src" / "pqlint"
    for py_file in src_dir.rglob("*.py"):
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_mod = alias.name.split(".")[0]
                    assert top_mod not in forbidden, (
                        f"{py_file.name}:{node.lineno} imports forbidden '{alias.name}'"
                    )
                    if alias.name.startswith("urllib.request") or alias.name.startswith(
                        "http.client"
                    ):
                        assert False, (
                            f"{py_file.name}:{node.lineno} imports forbidden '{alias.name}'"
                        )
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top_mod = node.module.split(".")[0]
                    assert top_mod not in forbidden, (
                        f"{py_file.name}:{node.lineno} imports from forbidden '{node.module}'"
                    )
                    if node.module.startswith("urllib.request") or node.module.startswith(
                        "http.client"
                    ):
                        assert False, (
                            f"{py_file.name}:{node.lineno} imports from forbidden '{node.module}'"
                        )
