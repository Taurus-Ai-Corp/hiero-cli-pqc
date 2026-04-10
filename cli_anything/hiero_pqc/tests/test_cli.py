"""Tests for hiero_pqc_cli — Click CLI commands.

Uses Click's CliRunner and mocks to avoid network/OpenSSL calls.
"""

import json
import unittest
from unittest.mock import patch, AsyncMock

from click.testing import CliRunner

from cli_anything.hiero_pqc.hiero_pqc_cli import cli


def _scan_result(domain="example.com", grade="WEAK", algo="RSA", size=2048, days=365):
    """Create a synthetic scan result."""
    return {
        "domain": domain,
        "status": "scanned",
        "crypto_grade": grade,
        "key_algorithm": f"{algo}Encryption" if algo == "RSA" else algo,
        "key_algorithm_display": algo,
        "key_size": size,
        "signature_algorithm": "sha256WithRSAEncryption",
        "issuer": "Test CA",
        "subject": f"CN = {domain}",
        "not_before": "Jan 01 00:00:00 2024 GMT",
        "not_after": "Jan 01 00:00:00 2027 GMT",
        "days_until_expiry": days,
        "sans": [domain, f"www.{domain}"],
        "grade_detail": "Weak — Quantum-vulnerable, migration recommended",
        "scan_timestamp": "2024-06-01T00:00:00Z",
    }


def _scan_error(domain="bad.com"):
    return {"domain": domain, "status": "error", "error": "Connection timeout (15s)"}


class TestCliNoCommand(unittest.TestCase):
    """Test CLI invoked without a subcommand."""

    def test_shows_version_and_commands(self):
        runner = CliRunner()
        result = runner.invoke(cli, [])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("hiero-cli-pqc", result.output)
        self.assertIn("scan", result.output)
        self.assertIn("report", result.output)
        self.assertIn("audit", result.output)


class TestInfoCommand(unittest.TestCase):
    """Test the 'info' command."""

    def test_info_text_output(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["info"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("hiero-cli-pqc", result.output)
        self.assertIn("Post-Quantum", result.output)
        self.assertIn("Capabilities", result.output)

    def test_info_json_output(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["info", "--json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["name"], "hiero-cli-pqc")
        self.assertIn("capabilities", data)
        self.assertIsInstance(data["capabilities"], list)
        self.assertIn("crypto_grades", data)


class TestScanCommand(unittest.TestCase):
    """Test the 'scan' command with mocked scan_domain."""

    @patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domain")
    def test_scan_success_text(self, mock_scan):
        mock_scan.return_value = _scan_result("test.com")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "test.com"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("test.com", result.output)
        self.assertIn("RSA", result.output)
        self.assertIn("WEAK", result.output)

    @patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domain")
    def test_scan_success_json(self, mock_scan):
        mock_scan.return_value = _scan_result("test.com")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "test.com", "--json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertTrue(data["success"])
        self.assertEqual(data["domain"], "test.com")
        self.assertEqual(data["crypto_grade"], "WEAK")

    @patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domain")
    def test_scan_error_exits_1(self, mock_scan):
        mock_scan.return_value = _scan_error("bad.com")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "bad.com"])
        self.assertEqual(result.exit_code, 1)

    @patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domain")
    def test_scan_error_json(self, mock_scan):
        mock_scan.return_value = _scan_error("bad.com")
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "bad.com", "--json"])
        self.assertEqual(result.exit_code, 1)
        data = json.loads(result.output)
        self.assertFalse(data["success"])


class TestScanBatchCommand(unittest.TestCase):
    """Test the 'scan-batch' command."""

    @patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domains")
    def test_scan_batch_success(self, mock_scan_domains):
        mock_scan_domains.return_value = [
            _scan_result("a.com"),
            _scan_result("b.com"),
        ]
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("domains.txt", "w") as f:
                f.write("a.com\nb.com\n")
            result = runner.invoke(cli, ["scan-batch", "domains.txt"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("2/2", result.output)

    @patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domains")
    def test_scan_batch_json_output(self, mock_scan_domains):
        mock_scan_domains.return_value = [
            _scan_result("a.com"),
            _scan_error("c.com"),
        ]
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("domains.txt", "w") as f:
                f.write("a.com\nc.com\n")
            result = runner.invoke(cli, ["scan-batch", "domains.txt", "--json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertTrue(data["success"])
        self.assertEqual(data["scanned"], 1)
        self.assertEqual(data["failed"], 1)

    def test_scan_batch_empty_file_exits_1(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            with open("empty.txt", "w") as f:
                f.write("# just a comment\n\n")
            result = runner.invoke(cli, ["scan-batch", "empty.txt"])
        self.assertEqual(result.exit_code, 1)

    def test_scan_batch_comments_and_blanks_filtered(self):
        """Comments (#) and blank lines are stripped from domain files."""
        with patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domains") as mock_scan:
            mock_scan.return_value = [_scan_result("real.com")]
            runner = CliRunner()
            with runner.isolated_filesystem():
                with open("domains.txt", "w") as f:
                    f.write("# This is a comment\n\nreal.com\n  \n# Another comment\n")
                runner.invoke(cli, ["scan-batch", "domains.txt"])
            # scan_domains should have been called with just ["real.com"]
            args = mock_scan.call_args[0][0]
            self.assertEqual(len(args), 1)
            self.assertEqual(args[0], "real.com")


class TestScoreCommand(unittest.TestCase):
    """Test the 'score' command."""

    def test_score_from_json_file(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            scan_data = {"results": [_scan_result("scored.com")]}
            with open("scan.json", "w") as f:
                json.dump(scan_data, f)
            result = runner.invoke(cli, ["score", "scan.json"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("scored.com", result.output)

    def test_score_json_output(self):
        runner = CliRunner()
        with runner.isolated_filesystem():
            scan_data = [_scan_result("scored.com")]
            with open("scan.json", "w") as f:
                json.dump(scan_data, f)
            result = runner.invoke(cli, ["score", "scan.json", "--json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertTrue(data["success"])
        self.assertEqual(data["total_scored"], 1)


class TestReportCommand(unittest.TestCase):
    """Test the 'report' command."""

    @patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domain")
    def test_report_text_output(self, mock_scan):
        mock_scan.return_value = _scan_result("report.com")
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "report.com"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("PQC COMPLIANCE ASSESSMENT REPORT", result.output)
        self.assertIn("report.com", result.output)

    @patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domain")
    def test_report_json_output(self, mock_scan):
        mock_scan.return_value = _scan_result("report.com")
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "report.com", "--json"])
        self.assertEqual(result.exit_code, 0)
        data = json.loads(result.output)
        self.assertEqual(data["report_type"], "pqc-compliance-assessment")

    @patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domain")
    def test_report_scan_failure(self, mock_scan):
        mock_scan.return_value = _scan_error("fail.com")
        runner = CliRunner()
        result = runner.invoke(cli, ["report", "fail.com"])
        self.assertEqual(result.exit_code, 1)

    @patch("cli_anything.hiero_pqc.hiero_pqc_cli.scan_domain")
    def test_report_writes_to_file(self, mock_scan):
        mock_scan.return_value = _scan_result("file.com")
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cli, ["report", "file.com", "--output", "out.txt"])
            self.assertEqual(result.exit_code, 0)
            with open("out.txt") as f:
                content = f.read()
            self.assertIn("PQC COMPLIANCE ASSESSMENT REPORT", content)


if __name__ == "__main__":
    unittest.main()
