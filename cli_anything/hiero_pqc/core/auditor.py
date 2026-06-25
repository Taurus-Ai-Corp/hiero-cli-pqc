     1|"""
     2|Hedera HCS Audit Trail — anchor PQC compliance reports to Hedera Consensus Service.
     3|
     4|Provides:
     5|- SHA-256 hash generation for reports
     6|- Hash verification against Hedera Mirror Node
     7|- HCS topic message lookup
     8|
     9|For submitting new messages to HCS, use @hashgraph/sdk (Node.js) or the
    10|Hedera SDK. This module handles the read/verify side via Mirror Node REST API.
    11|"""
    12|
    13|import hashlib
    14|import json
    15|import urllib.request
    16|import urllib.error
    17|import base64
    18|from datetime import datetime, timezone
    19|from typing import Any, Dict, List, Optional
    20|
    21|
    22|MIRROR_NODES = {
    23|    "mainnet": "https://mainnet-public.mirrornode.hedera.com",
    24|    "testnet": "https://testnet.mirrornode.hedera.com",
    25|    "previewnet": "https://previewnet.mirrornode.hedera.com",
    26|}
    27|
    28|
    29|def hash_report(report_data: Any) -> Dict[str, str]:
    30|    """Generate SHA-256 hash of a report for Hedera anchoring.
    31|
    32|    Args:
    33|        report_data: Dict, list, or string to hash.
    34|
    35|    Returns:
    36|        Dict with hash, algorithm, timestamp, and the canonical JSON used.
    37|    """
    38|    if isinstance(report_data, (dict, list)):
    39|        canonical = json.dumps(report_data, sort_keys=True, separators=(",", ":"))
    40|    else:
    41|        canonical = str(report_data)
    42|
    43|    sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    44|
    45|    return {
    46|        "hash": sha256,
    47|        "algorithm": "SHA-256",
    48|        "timestamp": datetime.now(timezone.utc).isoformat(),
    49|        "canonical_bytes": len(canonical.encode("utf-8")),
    50|    }
    51|
    52|
    53|def _mirror_get(network: str, path: str) -> tuple:
    54|    """GET request to Hedera Mirror Node."""
    55|    base_url = MIRROR_NODES.get(network)
    56|    if not base_url:
    57|        return {"error": f"Invalid network: {network}"}, 0
    58|
    59|    url = f"{base_url}{path}"
    60|    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    61|    try:
    62|        with urllib.request.urlopen(req, timeout=15) as resp:
    63|            return json.loads(resp.read().decode("utf-8")), resp.status
    64|    except urllib.error.HTTPError as e:
    65|        body = e.read().decode("utf-8", errors="replace")
    66|        try:
    67|            return json.loads(body), e.code
    68|        except json.JSONDecodeError:
    69|            return {"error": body}, e.code
    70|    except urllib.error.URLError as e:
    71|        return {"error": f"Mirror node unreachable: {e.reason}"}, 0
    72|    except Exception as e:
    73|        return {"error": f"Request failed: {str(e)}"}, 0
    74|
    75|
    76|def verify_hash_on_topic(
    77|    topic_id: str,
    78|    expected_hash: str,
    79|    network: str = "testnet",
    80|    limit: int = 100,
    81|) -> Dict[str, Any]:
    82|    """Search a Hedera HCS topic for a specific hash.
    83|
    84|    Args:
    85|        topic_id: Hedera topic ID (e.g., "0.0.12345").
    86|        expected_hash: SHA-256 hash to search for.
    87|        network: Hedera network (testnet, mainnet, previewnet).
    88|        limit: Max messages to search.
    89|
    90|    Returns:
    91|        Verification result with match status and message details if found.
    92|    """
    93|    data, status = _mirror_get(network, f"/api/v1/topics/{topic_id}/messages?limit={limit}")
    94|    if status != 200:
    95|        return {
    96|            "verified": False,
    97|            "error": data.get("error", f"HTTP {status}"),
    98|            "topic_id": topic_id,
    99|            "network": network,
   100|        }
   101|
   102|    messages = data.get("messages", [])
   103|    for msg in messages:
   104|        try:
   105|            decoded = base64.b64decode(msg.get("message", "")).decode("utf-8", errors="replace")
   106|        except Exception:
   107|            decoded = msg.get("message", "")
   108|
   109|        # Check if hash appears in the message (exact match or JSON field)
   110|        if expected_hash in decoded:
   111|            return {
   112|                "verified": True,
   113|                "topic_id": topic_id,
   114|                "network": network,
   115|                "sequence_number": msg.get("sequence_number"),
   116|                "consensus_timestamp": msg.get("consensus_timestamp"),
   117|                "message": decoded,
   118|                "running_hash": msg.get("running_hash", ""),
   119|            }
   120|
   121|        # Try parsing as JSON and check hash field
   122|        try:
   123|            parsed = json.loads(decoded)
   124|            if parsed.get("hash") == expected_hash or parsed.get("report_hash") == expected_hash:
   125|                return {
   126|                    "verified": True,
   127|                    "topic_id": topic_id,
   128|                    "network": network,
   129|                    "sequence_number": msg.get("sequence_number"),
   130|                    "consensus_timestamp": msg.get("consensus_timestamp"),
   131|                    "message": parsed,
   132|                    "running_hash": msg.get("running_hash", ""),
   133|                }
   134|        except (json.JSONDecodeError, AttributeError):
   135|            pass
   136|
   137|    return {
   138|        "verified": False,
   139|        "topic_id": topic_id,
   140|        "network": network,
   141|        "messages_searched": len(messages),
   142|        "error": f"Hash not found in {len(messages)} messages",
   143|    }
   144|
   145|
   146|def get_topic_messages(
   147|    topic_id: str,
   148|    network: str = "testnet",
   149|    limit: int = 10,
   150|) -> Dict[str, Any]:
   151|    """Get recent messages from a Hedera HCS topic.
   152|
   153|    Args:
   154|        topic_id: Hedera topic ID.
   155|        network: Hedera network.
   156|        limit: Max messages to return.
   157|
   158|    Returns:
   159|        Topic messages with decoded content.
   160|    """
   161|    data, status = _mirror_get(network, f"/api/v1/topics/{topic_id}/messages?limit={limit}")
   162|    if status != 200:
   163|        return {"success": False, "error": data.get("error", f"HTTP {status}")}
   164|
   165|    messages = []
   166|    for m in data.get("messages", []):
   167|        try:
   168|            decoded = base64.b64decode(m.get("message", "")).decode("utf-8", errors="replace")
   169|        except Exception:
   170|            decoded = m.get("message", "")
   171|
   172|        # Try to parse as JSON
   173|        try:
   174|            decoded = json.loads(decoded)
   175|        except (json.JSONDecodeError, TypeError):
   176|            pass
   177|
   178|        messages.append({
   179|            "sequence_number": m.get("sequence_number"),
   180|            "consensus_timestamp": m.get("consensus_timestamp"),
   181|            "message": decoded,
   182|        })
   183|
   184|    return {"success": True, "topic_id": topic_id, "network": network, "messages": messages}
   185|
   186|
   187|def generate_hcs_payload(
   188|    report_hash: str,
   189|    domain: str,
   190|    score: float,
   191|    grade: str,
   192|    service: str,
   193|) -> Dict[str, Any]:
   194|    """Generate a JSON payload suitable for HCS topic submission.
   195|
   196|    This payload can be submitted to Hedera HCS using @hashgraph/sdk
   197|    or any Hedera-compatible tool.
   198|
   199|    Args:
   200|        report_hash: SHA-256 hash of the compliance report.
   201|        domain: Scanned domain.
   202|        score: PQC urgency score (0-100).
   203|        grade: Crypto grade (CRITICAL, WEAK, etc.).
   204|        service: Recommended service tier.
   205|
   206|    Returns:
   207|        JSON-serializable payload (< 1KB for HCS message limit).
   208|    """
   209|    payload = {
   210|        "type": "pqc-audit",
   211|        "version": "1.0",
   212|        "report_hash": report_hash,
   213|        "domain": domain,
   214|        "pqc_score": score,
   215|        "crypto_grade": grade,
   216|        "recommended_service": service,
   217|        "timestamp": datetime.now(timezone.utc).isoformat(),
   218|        "auditor": "gridera-scan",
   219|    }
   220|
   221|    # Verify payload fits HCS message limit (1024 bytes)
   222|    encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
   223|    if len(encoded) > 1024:
   224|        # Trim domain if needed
   225|        payload["domain"] = domain[:50]
   226|        payload["recommended_service"] = service[:30]
   227|
   228|    return payload
   229|