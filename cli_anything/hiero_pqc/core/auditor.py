"""
Hedera HCS Audit Trail — anchor PQC compliance reports to Hedera Consensus Service.

Provides:
- SHA-256 hash generation for reports
- Hash verification against Hedera Mirror Node
- HCS topic message lookup

For submitting new messages to HCS, use @hashgraph/sdk (Node.js) or the
Hedera SDK. This module handles the read/verify side via Mirror Node REST API.
"""

import hashlib
import json
import urllib.request
import urllib.error
import base64
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


MIRROR_NODES = {
    "mainnet": "https://mainnet-public.mirrornode.hedera.com",
    "testnet": "https://testnet.mirrornode.hedera.com",
    "previewnet": "https://previewnet.mirrornode.hedera.com",
}


def hash_report(report_data: Any) -> Dict[str, str]:
    """Generate SHA-256 hash of a report for Hedera anchoring.

    Args:
        report_data: Dict, list, or string to hash.

    Returns:
        Dict with hash, algorithm, timestamp, and the canonical JSON used.
    """
    if isinstance(report_data, (dict, list)):
        canonical = json.dumps(report_data, sort_keys=True, separators=(",", ":"))
    else:
        canonical = str(report_data)

    sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    return {
        "hash": sha256,
        "algorithm": "SHA-256",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "canonical_bytes": len(canonical.encode("utf-8")),
    }


def _mirror_get(network: str, path: str) -> tuple:
    """GET request to Hedera Mirror Node."""
    base_url = MIRROR_NODES.get(network)
    if not base_url:
        return {"error": f"Invalid network: {network}"}, 0

    url = f"{base_url}{path}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body), e.code
        except json.JSONDecodeError:
            return {"error": body}, e.code
    except urllib.error.URLError as e:
        return {"error": f"Mirror node unreachable: {e.reason}"}, 0
    except Exception as e:
        return {"error": f"Request failed: {str(e)}"}, 0


def verify_hash_on_topic(
    topic_id: str,
    expected_hash: str,
    network: str = "testnet",
    limit: int = 100,
) -> Dict[str, Any]:
    """Search a Hedera HCS topic for a specific hash.

    Args:
        topic_id: Hedera topic ID (e.g., "0.0.12345").
        expected_hash: SHA-256 hash to search for.
        network: Hedera network (testnet, mainnet, previewnet).
        limit: Max messages to search.

    Returns:
        Verification result with match status and message details if found.
    """
    data, status = _mirror_get(network, f"/api/v1/topics/{topic_id}/messages?limit={limit}")
    if status != 200:
        return {
            "verified": False,
            "error": data.get("error", f"HTTP {status}"),
            "topic_id": topic_id,
            "network": network,
        }

    messages = data.get("messages", [])
    for msg in messages:
        try:
            decoded = base64.b64decode(msg.get("message", "")).decode("utf-8", errors="replace")
        except Exception:
            decoded = msg.get("message", "")

        # Check if hash appears in the message (exact match or JSON field)
        if expected_hash in decoded:
            return {
                "verified": True,
                "topic_id": topic_id,
                "network": network,
                "sequence_number": msg.get("sequence_number"),
                "consensus_timestamp": msg.get("consensus_timestamp"),
                "message": decoded,
                "running_hash": msg.get("running_hash", ""),
            }

        # Try parsing as JSON and check hash field
        try:
            parsed = json.loads(decoded)
            if parsed.get("hash") == expected_hash or parsed.get("report_hash") == expected_hash:
                return {
                    "verified": True,
                    "topic_id": topic_id,
                    "network": network,
                    "sequence_number": msg.get("sequence_number"),
                    "consensus_timestamp": msg.get("consensus_timestamp"),
                    "message": parsed,
                    "running_hash": msg.get("running_hash", ""),
                }
        except (json.JSONDecodeError, AttributeError):
            pass

    return {
        "verified": False,
        "topic_id": topic_id,
        "network": network,
        "messages_searched": len(messages),
        "error": f"Hash not found in {len(messages)} messages",
    }


def get_topic_messages(
    topic_id: str,
    network: str = "testnet",
    limit: int = 10,
) -> Dict[str, Any]:
    """Get recent messages from a Hedera HCS topic.

    Args:
        topic_id: Hedera topic ID.
        network: Hedera network.
        limit: Max messages to return.

    Returns:
        Topic messages with decoded content.
    """
    data, status = _mirror_get(network, f"/api/v1/topics/{topic_id}/messages?limit={limit}")
    if status != 200:
        return {"success": False, "error": data.get("error", f"HTTP {status}")}

    messages = []
    for m in data.get("messages", []):
        try:
            decoded = base64.b64decode(m.get("message", "")).decode("utf-8", errors="replace")
        except Exception:
            decoded = m.get("message", "")

        # Try to parse as JSON
        try:
            decoded = json.loads(decoded)
        except (json.JSONDecodeError, TypeError):
            pass

        messages.append({
            "sequence_number": m.get("sequence_number"),
            "consensus_timestamp": m.get("consensus_timestamp"),
            "message": decoded,
        })

    return {"success": True, "topic_id": topic_id, "network": network, "messages": messages}


def generate_hcs_payload(
    report_hash: str,
    domain: str,
    score: float,
    grade: str,
    service: str,
) -> Dict[str, Any]:
    """Generate a JSON payload suitable for HCS topic submission.

    This payload can be submitted to Hedera HCS using @hashgraph/sdk
    or any Hedera-compatible tool.

    Args:
        report_hash: SHA-256 hash of the compliance report.
        domain: Scanned domain.
        score: PQC urgency score (0-100).
        grade: Crypto grade (CRITICAL, WEAK, etc.).
        service: Recommended service tier.

    Returns:
        JSON-serializable payload (< 1KB for HCS message limit).
    """
    payload = {
        "type": "pqc-audit",
        "version": "1.0",
        "report_hash": report_hash,
        "domain": domain,
        "pqc_score": score,
        "crypto_grade": grade,
        "recommended_service": service,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "auditor": "hiero-cli-pqc",
    }

    # Verify payload fits HCS message limit (1024 bytes)
    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 1024:
        # Trim domain if needed
        payload["domain"] = domain[:50]
        payload["recommended_service"] = service[:30]

    return payload
