"""Tests for auditor network functions — verify_hash_on_topic, get_topic_messages, _mirror_get.

Uses unittest.mock to avoid real HTTP calls to Hedera Mirror Node.
"""

import base64
import json
import unittest
from unittest.mock import patch, MagicMock
import urllib.error

from cli_anything.hiero_pqc.core.auditor import (
    _mirror_get,
    verify_hash_on_topic,
    get_topic_messages,
    MIRROR_NODES,
)


def _b64(text):
    """Encode text as base64 string (for mocking HCS messages)."""
    return base64.b64encode(text.encode("utf-8")).decode("utf-8")


def _mock_urlopen_response(data, status=200):
    """Create a mock response for urllib.request.urlopen."""
    resp = MagicMock()
    resp.read.return_value = json.dumps(data).encode("utf-8")
    resp.status = status
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


class TestMirrorGet(unittest.TestCase):
    """Test _mirror_get HTTP helper."""

    def test_invalid_network_returns_error(self):
        data, status = _mirror_get("invalidnet", "/api/v1/topics/0.0.1/messages")
        self.assertEqual(status, 0)
        self.assertIn("Invalid network", data["error"])

    @patch("cli_anything.hiero_pqc.core.auditor.urllib.request.urlopen")
    def test_successful_request(self, mock_urlopen):
        mock_urlopen.return_value = _mock_urlopen_response({"messages": []}, 200)
        data, status = _mirror_get("testnet", "/api/v1/topics/0.0.1/messages")
        self.assertEqual(status, 200)
        self.assertEqual(data, {"messages": []})

    @patch("cli_anything.hiero_pqc.core.auditor.urllib.request.urlopen")
    def test_http_error_returns_status_code(self, mock_urlopen):
        error_resp = MagicMock()
        error_resp.read.return_value = b'{"error": "not found"}'
        error_resp.code = 404
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test", code=404, msg="Not Found",
            hdrs=None, fp=error_resp,
        )
        data, status = _mirror_get("testnet", "/api/v1/topics/0.0.999/messages")
        self.assertEqual(status, 404)
        self.assertIn("error", data)

    @patch("cli_anything.hiero_pqc.core.auditor.urllib.request.urlopen")
    def test_http_error_non_json_body(self, mock_urlopen):
        error_resp = MagicMock()
        error_resp.read.return_value = b"<html>Server Error</html>"
        error_resp.code = 500
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="http://test", code=500, msg="Internal Server Error",
            hdrs=None, fp=error_resp,
        )
        data, status = _mirror_get("testnet", "/some/path")
        self.assertEqual(status, 500)
        self.assertIn("Server Error", data["error"])

    @patch("cli_anything.hiero_pqc.core.auditor.urllib.request.urlopen")
    def test_url_error_unreachable(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        data, status = _mirror_get("testnet", "/api/v1/topics/0.0.1/messages")
        self.assertEqual(status, 0)
        self.assertIn("unreachable", data["error"])

    @patch("cli_anything.hiero_pqc.core.auditor.urllib.request.urlopen")
    def test_generic_exception(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("timed out")
        data, status = _mirror_get("testnet", "/api/v1/topics/0.0.1/messages")
        self.assertEqual(status, 0)
        self.assertIn("Request failed", data["error"])

    def test_all_networks_have_urls(self):
        for network in ("mainnet", "testnet", "previewnet"):
            self.assertIn(network, MIRROR_NODES)
            self.assertTrue(MIRROR_NODES[network].startswith("https://"))


class TestVerifyHashOnTopic(unittest.TestCase):
    """Test verify_hash_on_topic hash searching logic."""

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_hash_found_in_plaintext(self, mock_get):
        """Hash appears as substring in decoded message."""
        target_hash = "abc123def456"
        mock_get.return_value = (
            {"messages": [
                {"message": _b64(f"audit report hash: {target_hash}"),
                 "sequence_number": 1, "consensus_timestamp": "1234.567"},
            ]},
            200,
        )
        result = verify_hash_on_topic("0.0.123", target_hash)
        self.assertTrue(result["verified"])
        self.assertEqual(result["sequence_number"], 1)

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_hash_found_in_json_report_hash_field(self, mock_get):
        """Hash found via parsed JSON report_hash field."""
        target_hash = "deadbeef1234"
        msg_json = json.dumps({"report_hash": target_hash, "domain": "test.com"})
        mock_get.return_value = (
            {"messages": [
                {"message": _b64(msg_json),
                 "sequence_number": 5, "consensus_timestamp": "5678.901"},
            ]},
            200,
        )
        result = verify_hash_on_topic("0.0.456", target_hash)
        self.assertTrue(result["verified"])
        self.assertEqual(result["sequence_number"], 5)

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_hash_found_in_json_hash_field(self, mock_get):
        """Hash found via parsed JSON 'hash' field."""
        target_hash = "face0ff0"
        msg_json = json.dumps({"hash": target_hash, "algo": "SHA-256"})
        mock_get.return_value = (
            {"messages": [
                {"message": _b64(msg_json),
                 "sequence_number": 3, "consensus_timestamp": "111.222"},
            ]},
            200,
        )
        result = verify_hash_on_topic("0.0.789", target_hash)
        self.assertTrue(result["verified"])

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_hash_not_found(self, mock_get):
        mock_get.return_value = (
            {"messages": [
                {"message": _b64("some other content"), "sequence_number": 1},
            ]},
            200,
        )
        result = verify_hash_on_topic("0.0.123", "not_in_any_message")
        self.assertFalse(result["verified"])
        self.assertEqual(result["messages_searched"], 1)

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_http_failure_returns_unverified(self, mock_get):
        mock_get.return_value = ({"error": "HTTP 500"}, 500)
        result = verify_hash_on_topic("0.0.123", "somehash")
        self.assertFalse(result["verified"])
        self.assertIn("error", result)

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_invalid_base64_message_handled(self, mock_get):
        """Messages with invalid base64 don't crash the search."""
        mock_get.return_value = (
            {"messages": [
                {"message": "!!!not-valid-base64!!!", "sequence_number": 1},
            ]},
            200,
        )
        result = verify_hash_on_topic("0.0.123", "somehash")
        # Should not crash, just not find the hash
        self.assertFalse(result["verified"])


class TestGetTopicMessages(unittest.TestCase):
    """Test get_topic_messages decoding and formatting."""

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_success_decodes_base64_messages(self, mock_get):
        mock_get.return_value = (
            {"messages": [
                {"message": _b64("hello world"), "sequence_number": 1,
                 "consensus_timestamp": "100.200"},
                {"message": _b64("second msg"), "sequence_number": 2,
                 "consensus_timestamp": "100.300"},
            ]},
            200,
        )
        result = get_topic_messages("0.0.123", "testnet", limit=10)
        self.assertTrue(result["success"])
        self.assertEqual(len(result["messages"]), 2)
        self.assertEqual(result["messages"][0]["message"], "hello world")
        self.assertEqual(result["messages"][1]["message"], "second msg")

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_json_messages_parsed(self, mock_get):
        """JSON content inside base64 is parsed into dicts."""
        payload = {"type": "pqc-audit", "domain": "test.com"}
        mock_get.return_value = (
            {"messages": [
                {"message": _b64(json.dumps(payload)), "sequence_number": 1,
                 "consensus_timestamp": "100.200"},
            ]},
            200,
        )
        result = get_topic_messages("0.0.123")
        self.assertTrue(result["success"])
        self.assertIsInstance(result["messages"][0]["message"], dict)
        self.assertEqual(result["messages"][0]["message"]["domain"], "test.com")

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_http_failure(self, mock_get):
        mock_get.return_value = ({"error": "not found"}, 404)
        result = get_topic_messages("0.0.999")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_invalid_base64_falls_back_to_raw(self, mock_get):
        mock_get.return_value = (
            {"messages": [
                {"message": "plain-text-not-b64", "sequence_number": 1,
                 "consensus_timestamp": "100.200"},
            ]},
            200,
        )
        result = get_topic_messages("0.0.123")
        self.assertTrue(result["success"])
        # Falls back to raw string
        self.assertEqual(result["messages"][0]["message"], "plain-text-not-b64")

    @patch("cli_anything.hiero_pqc.core.auditor._mirror_get")
    def test_empty_messages(self, mock_get):
        mock_get.return_value = ({"messages": []}, 200)
        result = get_topic_messages("0.0.123")
        self.assertTrue(result["success"])
        self.assertEqual(len(result["messages"]), 0)


if __name__ == "__main__":
    unittest.main()
